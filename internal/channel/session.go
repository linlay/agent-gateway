package channel

import (
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"agent-gateway/internal/auth"
	"agent-gateway/internal/id"

	"github.com/gorilla/websocket"
)

type Session struct {
	id        string
	identity  auth.PlatformIdentity
	socket    *websocket.Conn
	logger    *slog.Logger
	send      chan []byte
	done      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
	pendingMu sync.Mutex
	pending   map[string]chan []byte
	stageMu   sync.Mutex
	stage     *stagedSnapshot
}

func newSession(identity auth.PlatformIdentity, socket *websocket.Conn, writeQueueSize int, logger *slog.Logger) *Session {
	return &Session{id: id.New("chs"), identity: identity, socket: socket, logger: logger, send: make(chan []byte, writeQueueSize), done: make(chan struct{}), pending: map[string]chan []byte{}}
}

func (s *Session) Run(handle func([]byte)) {
	go s.writeLoop()
	s.socket.SetPongHandler(func(string) error { _ = s.socket.SetReadDeadline(time.Now().Add(90 * time.Second)); return nil })
	_ = s.socket.SetReadDeadline(time.Now().Add(90 * time.Second))
	for {
		messageType, raw, err := s.socket.ReadMessage()
		if err != nil {
			break
		}
		if messageType != websocket.TextMessage {
			continue
		}
		handle(raw)
	}
	s.closeInternal()
}

func (s *Session) writeLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case raw := <-s.send:
			_ = s.socket.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if err := s.socket.WriteMessage(websocket.TextMessage, raw); err != nil {
				s.closeInternal()
				return
			}
		case <-ticker.C:
			_ = s.socket.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if err := s.socket.WriteMessage(websocket.PingMessage, nil); err != nil {
				s.closeInternal()
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *Session) Send(value any) error {
	if s.Closed() {
		return errors.New("channel closed")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	select {
	case s.send <- raw:
		return nil
	case <-s.done:
		return errors.New("channel closed")
	case <-time.After(5 * time.Second):
		s.Close(1013, "write queue overflow")
		return errors.New("channel write queue overflow")
	}
}

func (s *Session) OpenRequest(frame RequestFrame) (<-chan []byte, func(), error) {
	frames := make(chan []byte, 64)
	s.pendingMu.Lock()
	if s.Closed() {
		s.pendingMu.Unlock()
		return nil, nil, errors.New("channel closed")
	}
	if _, exists := s.pending[frame.ID]; exists {
		s.pendingMu.Unlock()
		return nil, nil, errors.New("duplicate request id")
	}
	s.pending[frame.ID] = frames
	s.pendingMu.Unlock()
	cleanupOnce := sync.Once{}
	cleanup := func() {
		cleanupOnce.Do(func() {
			s.pendingMu.Lock()
			if current := s.pending[frame.ID]; current == frames {
				delete(s.pending, frame.ID)
				close(frames)
			}
			s.pendingMu.Unlock()
		})
	}
	if err := s.Send(frame); err != nil {
		cleanup()
		return nil, nil, err
	}
	return frames, cleanup, nil
}

func (s *Session) Deliver(requestID string, raw []byte, frameType string) {
	s.pendingMu.Lock()
	frames := s.pending[requestID]
	if frames == nil {
		s.pendingMu.Unlock()
		return
	}
	terminal := frameType == FrameResponse || frameType == FrameError
	if frameType == FrameStream {
		var frame StreamFrame
		if json.Unmarshal(raw, &frame) == nil && len(frame.Event) == 0 {
			terminal = true
		}
	}
	select {
	case frames <- append([]byte(nil), raw...):
	default:
		s.pendingMu.Unlock()
		s.Close(1013, "request consumer backpressure")
		return
	}
	if terminal {
		delete(s.pending, requestID)
		close(frames)
	}
	s.pendingMu.Unlock()
}

func (s *Session) Close(code int, reason string) {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		_ = s.socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
		_ = s.socket.Close()
		close(s.done)
		s.closePending()
	})
}
func (s *Session) closeInternal() {
	s.closeOnce.Do(func() { s.closed.Store(true); _ = s.socket.Close(); close(s.done); s.closePending() })
}
func (s *Session) closePending() {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for key, frames := range s.pending {
		delete(s.pending, key)
		close(frames)
	}
}
func (s *Session) Closed() bool { return s == nil || s.closed.Load() }
func (s *Session) PendingCount() int {
	if s == nil {
		return 0
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	return len(s.pending)
}
