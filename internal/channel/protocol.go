package channel

import (
	"encoding/json"

	"agent-gateway/internal/domain"
)

const (
	FrameRequest  = "request"
	FrameResponse = "response"
	FrameStream   = "stream"
	FramePush     = "push"
	FrameError    = "error"
)

type RequestFrame struct {
	Frame   string          `json:"frame"`
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type ResponseFrame struct {
	Frame string `json:"frame"`
	Type  string `json:"type"`
	ID    string `json:"id"`
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Data  any    `json:"data,omitempty"`
}

type ErrorFrame struct {
	Frame string `json:"frame"`
	Type  string `json:"type"`
	ID    string `json:"id,omitempty"`
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Data  any    `json:"data,omitempty"`
}

type StreamFrame struct {
	Frame    string          `json:"frame"`
	ID       string          `json:"id"`
	StreamID string          `json:"streamId,omitempty"`
	Event    json.RawMessage `json:"event,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	LastSeq  int64           `json:"lastSeq,omitempty"`
}

type CatalogBegin = domain.CatalogBegin

type CardUpdate = domain.CardUpdate

type CatalogCommit struct {
	SnapshotID string `json:"snapshotId"`
	Revision   int64  `json:"revision"`
	CardCount  int    `json:"cardCount"`
	Digest     string `json:"digest,omitempty"`
}

func Payload(value any) json.RawMessage {
	if value == nil {
		return nil
	}
	raw, _ := json.Marshal(value)
	return raw
}
