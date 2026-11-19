package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/logging"
)

// bridgeSidecarEvents keeps the API's broker fed from the sidecar's event stream.
//
// Why this exists: the sidecar publishes WafEvents into its own in-process broker,
// which lives in the engine process. The API has a different broker, so without a
// bridge GET /api/v1/events/history is permanently empty and the dashboard opens
// with nothing even while the WAF is blocking traffic. The alternative — having the
// engine POST events with a service JWT — needs a token to be minted, rotated and
// kept alive; the Unix socket is already the trust boundary between the two
// processes, so the API simply consumes the stream it already has access to.
func (s *Server) bridgeSidecarEvents(ctx context.Context) {
	socket := s.cfg.Sidecar.SocketPath
	if socket == "" {
		logging.Warn().Msg("no sidecar socket configured; event history will stay empty")
		return
	}

	backoff := time.Second
	for ctx.Err() == nil {
		err := s.consumeSidecarEvents(ctx, socket)
		if ctx.Err() != nil {
			return
		}
		logging.Warn().Err(err).Str("socket", socket).Msg("sidecar event stream ended; reconnecting")
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
}

// consumeSidecarEvents reads the sidecar's SSE stream until it closes.
func (s *Server) consumeSidecarEvents(ctx context.Context, socket string) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
		// No overall timeout: this is a long-lived stream. The context ends it.
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sidecar/events", nil)
	if err != nil {
		return fmt.Errorf("building sidecar request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to the sidecar: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sidecar event stream returned %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 8<<10), 1<<20)

	var data strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		case line == "":
			// A blank line ends the frame.
			if data.Len() > 0 {
				s.publishBridgedEvent(data.String())
				data.Reset()
			}
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading the sidecar stream: %w", err)
	}
	return nil
}

// publishBridgedEvent validates and republishes one frame into the API broker.
func (s *Server) publishBridgedEvent(raw string) {
	var ev events.WafEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		logging.Warn().Err(err).Msg("discarding a sidecar event that is not valid JSON")
		return
	}
	if err := ev.Validate(); err != nil {
		logging.Warn().Err(err).Msg("discarding an invalid sidecar event")
		return
	}
	if s.broker != nil {
		s.broker.Publish(ev)
	}
}
