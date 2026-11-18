package catalog

// Aho–Corasick over the catalog's literal patterns.
//
// Why: the first implementation asked strings.Contains once per pattern per
// field, which is O(patterns x len). With a 64 KB body at the inspection cap that
// measured 3.7 ms and 263 KB of allocation per request — a WAF that can be
// tripped into using 3.7 ms of CPU with one request is a denial-of-service tool
// pointed at itself, and it breaks the sub-2ms budget in Constitution §1.2.
//
// A scan here is one pass over the bytes regardless of how many rules exist,
// which is what lets the catalog grow to hundreds of signatures without costing
// more per request. Fail links are precomputed once at load time.

// automaton is built once per catalog and never mutated afterwards, so it is safe
// for concurrent evaluation without a lock.
type automaton struct {
	// next[state][byte] is the transition, or -1 when absent.
	next [][256]int32
	fail []int32
	// out lists the pattern indices that end at each state, including the ones
	// inherited through fail links (merged during construction).
	out [][]int32
}

// buildAutomaton compiles every pattern. Patterns must already be normalised the
// same way the request is, so the automaton matches decoded text.
func buildAutomaton(patterns []string) *automaton {
	a := &automaton{
		next: [][256]int32{newState()},
		fail: []int32{0},
		out:  [][]int32{nil},
	}

	for idx, p := range patterns {
		state := int32(0)
		for i := 0; i < len(p); i++ {
			c := p[i]
			next := a.next[state][c]
			if next == -1 {
				a.next[state][c] = stateIdx(len(a.next))
				a.next = append(a.next, newState())
				a.fail = append(a.fail, 0)
				a.out = append(a.out, nil)
				next = stateIdx(len(a.next) - 1)
			}
			state = next
		}
		a.out[state] = append(a.out[state], int32(idx))
	}

	a.buildFailLinks()
	return a
}

// stateIdx narrows a state number, which is bounded by the catalog's total
// pattern length (thousands of bytes), far below int32.
//
//nolint:gosec // G115: see above; the value comes from a checked-in file, not the request.
func stateIdx(n int) int32 { return int32(n) }

func newState() [256]int32 {
	var s [256]int32
	for i := range s {
		s[i] = -1
	}
	return s
}

// buildFailLinks walks the automaton breadth-first, the standard construction:
// the failure of a child is the longest proper suffix that is also a prefix.
func (a *automaton) buildFailLinks() {
	queue := make([]int32, 0, len(a.next))

	for c := 0; c < 256; c++ {
		child := a.next[0][c]
		switch child {
		case -1:
			// From the root, a missing transition stays at the root.
			a.next[0][c] = 0
		default:
			a.fail[child] = 0
			queue = append(queue, child)
		}
	}

	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]

		// Inherit the failure state's outputs: a pattern that ends there ends here
		// as well.
		a.out[state] = append(a.out[state], a.out[a.fail[state]]...)

		for c := 0; c < 256; c++ {
			child := a.next[state][c]
			if child == -1 {
				continue
			}
			f := a.fail[state]
			for a.next[f][c] == -1 {
				f = a.fail[f]
			}
			a.fail[child] = a.next[f][c]
			queue = append(queue, child)
		}
	}
}

// scan sets a bit for every pattern that occurs in b. hits must be sized by
// patternHitsWords.
func (a *automaton) scan(b []byte, hits []uint64) {
	if len(b) == 0 {
		return
	}

	state := int32(0)
	for i := 0; i < len(b); i++ {
		c := b[i]
		for a.next[state][c] == -1 {
			state = a.fail[state]
		}
		state = a.next[state][c]
		for _, p := range a.out[state] {
			hits[p>>6] |= 1 << (p & 63)
		}
	}
}

// patternHitsWords is how many uint64 words a per-field hit set needs.
func patternHitsWords(patterns int) int {
	if patterns == 0 {
		return 1
	}
	return (patterns + 63) / 64
}

func bitsetGet(bits []uint64, i int32) bool {
	return bits[i>>6]&(1<<(i&63)) != 0
}
