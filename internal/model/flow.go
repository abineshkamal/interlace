// Package model holds the core data types shared across Interlace.
package model

import (
	"net/http"
	"time"
)

// Flow is a single captured request/response exchange that passed through the
// proxy. Bodies are stored raw; headers are stored as serialized JSON by the
// store layer.
type Flow struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`

	// Request
	Method     string      `json:"method"`
	Scheme     string      `json:"scheme"`
	Host       string      `json:"host"`
	Path       string      `json:"path"`
	URL        string      `json:"url"`
	ReqHeaders http.Header `json:"reqHeaders"`
	ReqBody    []byte      `json:"reqBody"`

	// Response
	StatusCode  int         `json:"statusCode"`
	RespHeaders http.Header `json:"respHeaders"`
	RespBody    []byte      `json:"respBody"`
	ContentType string      `json:"contentType"`

	// RespLen is the stored response body size. It is populated for list rows
	// (which do not load bodies) so summaries can show length cheaply.
	RespLen int `json:"respLen"`

	DurationMs int64  `json:"durationMs"`
	Error      string `json:"error,omitempty"`
}

// WSMessage is a single WebSocket frame observed through the proxy.
type WSMessage struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"time"`
	Host      string    `json:"host"`
	URL       string    `json:"url"`
	Direction string    `json:"direction"` // "send" (client→server) or "recv" (server→client)
	Opcode    string    `json:"opcode"`    // "text" | "binary"
	Payload   string    `json:"payload"`
}
