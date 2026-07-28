//go:build linux && cgo
// +build linux,cgo

package appsec

/*
#cgo LDFLAGS: -L${SRCDIR}/../../third_party/open-appsec -lwaffynx_bridge -lstdc++ -Wl,-rpath,${SRCDIR}/../../third_party/open-appsec
#cgo CFLAGS: -I${SRCDIR}/../../third_party/open-appsec

#include "waffynx_bridge.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

type CPPBridgeScorer struct {
	enabled      bool
	bridge       *C.waffynx_bridge_t
	waapDataPath string
}

func NewCPPBridgeScorer(waapDataPath string) (*CPPBridgeScorer, error) {
	s := &CPPBridgeScorer{
		waapDataPath: waapDataPath,
	}

	if waapDataPath == "" {
		s.enabled = false
		return s, nil
	}

	cPath := C.CString(waapDataPath)
	defer C.free(unsafe.Pointer(cPath))

	bridge := C.waffynx_bridge_init(cPath, 2)
	if bridge == nil {
		s.enabled = false
		return s, nil
	}

	s.bridge = bridge
	s.enabled = true
	return s, nil
}

func (s *CPPBridgeScorer) Name() string {
	if s.enabled {
		return "open-appsec-cpp"
	}
	return "open-appsec-cpp (stub)"
}

func (s *CPPBridgeScorer) Health(ctx context.Context) error {
	if !s.enabled {
		return fmt.Errorf("CPP bridge not initialized (no waap.data)")
	}
	return nil
}

func (s *CPPBridgeScorer) Close() error {
	if s.bridge != nil {
		C.waffynx_bridge_destroy(s.bridge)
		s.bridge = nil
	}
	return nil
}

func (s *CPPBridgeScorer) Evaluate(ctx context.Context, features *Features) (*Result, error) {
	if !s.enabled {
		return &Result{
			Verdict:    VerdictAllow,
			Score:      0.0,
			Confidence: 1.0,
			ModelName:  s.Name(),
		}, nil
	}

	var req C.waffynx_request_t
	req.method = cStrOrNull(features.Method)
	req.uri = cStrOrNull(features.URI)
	req.host = cStrOrNull(features.Host)
	req.client_ip = cStrOrNull(features.ClientIP)
	req.user_agent = cStrOrNull(features.UserAgent)
	req.content_type = cStrOrNull(features.ContentType)

	if len(features.Body) > 0 {
		req.body = C.CString(string(features.Body))
		req.body_len = C.int(len(features.Body))
		defer C.free(unsafe.Pointer(req.body))
	} else {
		req.body = nil
		req.body_len = 0
	}

	result := C.waffynx_bridge_evaluate(s.bridge, &req)

	verdict := VerdictAllow
	if result.should_block != 0 {
		verdict = VerdictBlock
	}

	return &Result{
		Verdict:    verdict,
		Score:      float64(result.score),
		Confidence: float64(result.confidence),
		Reasons:    []string{C.GoString(&result.reasons[0])},
		Anomalies:  []string{C.GoString(&result.anomalies[0])},
		ModelName:  s.Name(),
	}, nil
}

func cStrOrNull(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}
