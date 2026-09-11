package api

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/events"
)

func (s *Server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		s.writeJSON(w, r, http.StatusOK, []audit.Event{})
		return
	}

	limit := 100
	actor := r.URL.Query().Get("actor")
	action := r.URL.Query().Get("action")
	result := r.URL.Query().Get("result")

	queryEvents := s.audit.Query(audit.QueryFilter{
		Limit:  limit,
		Actor:  actor,
		Action: action,
		Result: result,
	})

	s.writeJSON(w, r, http.StatusOK, queryEvents)
}

func (s *Server) handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	if s.broker == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "event broker not available")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, events.MaxEventBodyBytes)
	var evt events.WafEvent
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&evt); err != nil {
		if err == io.EOF {
			s.writeError(w, r, http.StatusBadRequest, "empty event body")
			return
		}
		s.writeError(w, r, http.StatusBadRequest, "invalid event body")
		return
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		s.writeError(w, r, http.StatusBadRequest, "event body must contain one JSON object")
		return
	}
	if err := evt.Validate(); err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	s.broker.Publish(evt)
	s.writeJSON(w, r, http.StatusAccepted, map[string]string{"status": "ingested"})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, r, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var eventCh <-chan []byte
	if s.broker != nil {
		ch := s.broker.Subscribe()
		defer s.broker.Unsubscribe(ch)
		eventCh = ch
	}

	s.writeSSEStats(w, flusher)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-eventCh:
			w.Write([]byte("data: "))
			w.Write(data)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		case <-ticker.C:
			s.writeSSEStats(w, flusher)
		}
	}
}

func (s *Server) writeSSEStats(w http.ResponseWriter, flusher http.Flusher) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	cfg := s.readConfig()
	if cfg == nil {
		cfg = &config.Config{}
	}

	data, _ := json.Marshal(map[string]interface{}{
		"type":       "stats",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"goroutines": runtime.NumGoroutine(),
		"heap_mb":    float64(mem.Alloc) / 1024 / 1024,
		"engine":     cfg.AppSec.Engine,
	})
	w.Write([]byte("data: "))
	w.Write(data)
	w.Write([]byte("\n\n"))
	flusher.Flush()
}
