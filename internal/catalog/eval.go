package catalog

import (
	"strings"
	"sync"

	"github.com/jackby03/waffynx/internal/policy"
)

// Hit is a rule that fired.
type Hit struct {
	RuleID   string
	Name     string
	Severity Severity
	Action   Action
	Field    Field
	// Pattern is the normalised signature that matched. Useful in an event, and
	// safe to store: it is the catalog's text, not the request's.
	Pattern string
}

// fieldCount is the number of inspectable inputs, fixed by the automation layout.
const fieldCount = 7

const (
	// idxMethod..idxReferer mirror fieldIndex and index into the per-field caches.
	idxMethod = iota
	idxPath
	idxQuery
	idxBody
	idxHeaders
	idxUserAgent
	idxReferer
)

// Evaluate returns the first rule that matches, or nil.
//
// Each inspected field is normalised and scanned exactly once, no matter how many
// rules exist; the automaton reports every pattern that occurred, and rules are
// then resolved against those bits. The previous per-rule strings.Contains loop
// cost 3.7 ms on a 64 KB body — a request-sized denial of service.
//
// The catalog is immutable at runtime, so no lock is taken on the hot path.
func (c *Catalog) Evaluate(req *policy.Request) *Hit {
	if req == nil || len(c.Rules) == 0 {
		return nil
	}

	// Two bitsets per inspected field: the raw value and the decoded one, because
	// a rule chooses which it means ("nikto" must not match a decoded user-agent).
	// Both the bitsets and the normalisation scratch come from a pool: at 4.6 KB
	// per request this was visible GC pressure on the hot path.
	sc := c.takeScratch()
	defer c.putScratch(sc)

	bits := sc.bits
	for i := range bits {
		bits[i] = 0
	}
	method := strings.ToUpper(req.Method)

	buf := sc.buf[:0]
	for f := 0; f < fieldCount; f++ {
		if !c.rawUsed[f] && !c.decUsed[f] {
			continue
		}
		raw := extractBytes(req, FieldByIndex(f))

		if c.rawUsed[f] {
			base := f * c.hitsWords
			c.auto.scan(normalizeInto(buf, raw, false), bits[base:base+c.hitsWords])
		}
		if c.decUsed[f] {
			base := (fieldCount + f) * c.hitsWords
			c.auto.scan(normalizeInto(buf, raw, true), bits[base:base+c.hitsWords])
		}
	}

	for i := range c.Rules {
		r := &c.Rules[i]
		if r.method != nil && !r.method[method] {
			continue
		}

		decoded := r.Decoded == nil || *r.Decoded
		for _, f := range r.fields {
			idx := fieldIndex(f)
			if idx < 0 {
				continue
			}
			base := idx * c.hitsWords
			if decoded {
				base = (fieldCount + idx) * c.hitsWords
			}
			fieldBits := bits[base : base+c.hitsWords]

			if idxAny(fieldBits, r.noneOfIdx) {
				continue
			}
			if p, ok := firstIdx(fieldBits, r.anyOfIdx); ok {
				return &Hit{
					RuleID:   r.ID,
					Name:     r.Name,
					Severity: r.Severity,
					Action:   r.Action,
					Field:    f,
					Pattern:  c.patterns[p],
				}
			}
		}
	}
	return nil
}

// FieldByIndex reverses fieldIndex.
func FieldByIndex(i int) Field {
	switch i {
	case idxMethod:
		return FieldMethod
	case idxPath:
		return FieldPath
	case idxQuery:
		return FieldQuery
	case idxBody:
		return FieldBody
	case idxHeaders:
		return FieldHeaders
	case idxUserAgent:
		return FieldUserAgent
	case idxReferer:
		return FieldReferer
	}
	return ""
}

func fieldIndex(f Field) int {
	switch f {
	case FieldMethod:
		return idxMethod
	case FieldPath:
		return idxPath
	case FieldQuery:
		return idxQuery
	case FieldBody:
		return idxBody
	case FieldHeaders:
		return idxHeaders
	case FieldUserAgent:
		return idxUserAgent
	case FieldReferer:
		return idxReferer
	}
	return -1
}

// extract reads one input from the request, without normalising it.
func extractBytes(req *policy.Request, f Field) []byte {
	switch f {
	case FieldMethod:
		return []byte(req.Method)
	case FieldPath:
		if i := strings.IndexByte(req.Path, '?'); i >= 0 {
			return []byte(req.Path[:i])
		}
		return []byte(req.Path)
	case FieldQuery:
		if i := strings.IndexByte(req.Path, '?'); i >= 0 {
			return []byte(req.Path[i+1:])
		}
		return nil
	case FieldBody:
		// The module caps the body before it reaches the sidecar; the limit here is
		// a second guard so a direct caller cannot make the catalog scan megabytes.
		const maxBody = 64 << 10
		if len(req.Body) > maxBody {
			return req.Body[:maxBody]
		}
		return req.Body
	case FieldHeaders:
		if len(req.Headers) == 0 {
			return nil
		}
		var b strings.Builder
		for _, vs := range req.Headers {
			for _, v := range vs {
				b.WriteString(v)
				b.WriteByte(0x0a)
			}
		}
		return []byte(b.String())
	case FieldUserAgent:
		return []byte(firstHeader(req, "User-Agent"))
	case FieldReferer:
		return []byte(firstHeader(req, "Referer"))
	}
	return nil
}

// scratch holds the per-evaluation buffers so a request does not allocate 4.6 KB
// of short-lived memory. Evaluation never yields to another request mid-scan, so
// one buffer per in-flight evaluation is enough.
type scratch struct {
	bits []uint64
	buf  []byte
}

var scratchPool = sync.Pool{New: func() any { return &scratch{} }}

func (c *Catalog) takeScratch() *scratch {
	sc, _ := scratchPool.Get().(*scratch)
	if sc == nil {
		sc = &scratch{}
	}
	if need := 2 * fieldCount * c.hitsWords; len(sc.bits) < need {
		sc.bits = make([]uint64, need)
	}
	// Capacity, not length: putScratch truncates the buffer to zero length, so a
	// length check would reallocate 64 KB on every request and the pool would be
	// pure overhead (measured: 19.6 us/op instead of 6.9).
	if need := c.bodyCeiling; cap(sc.buf) < need {
		sc.buf = make([]byte, need)
	} else {
		sc.buf = sc.buf[:need]
	}
	return sc
}

func (c *Catalog) putScratch(sc *scratch) {
	sc.buf = sc.buf[:0]
	scratchPool.Put(sc)
}

func firstHeader(req *policy.Request, name string) string {
	if vs, ok := req.Headers[name]; ok && len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func idxAny(bits []uint64, idxs []int32) bool {
	for _, i := range idxs {
		if bitsetGet(bits, i) {
			return true
		}
	}
	return false
}

func firstIdx(bits []uint64, idxs []int32) (int32, bool) {
	for _, i := range idxs {
		if bitsetGet(bits, i) {
			return i, true
		}
	}
	return 0, false
}
