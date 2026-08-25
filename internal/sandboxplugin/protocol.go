package sandboxplugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
)

const (
	ProtocolVersion        = "envvault.sandbox-plugin/v1"
	defaultMaxMessageBytes = 256 << 10
	defaultCleanupTimeout  = 5 * time.Second
)

type ProtocolRequest struct {
	Protocol string           `json:"protocol"`
	ID       string           `json:"id"`
	Method   string           `json:"method"`
	Describe *DescribeRequest `json:"describe,omitempty"`
	Open     *OpenRequest     `json:"open,omitempty"`
	Close    *CloseRequest    `json:"close,omitempty"`
}

type CloseRequest struct {
	LeaseID string `json:"lease_id"`
}

type ProtocolResponse struct {
	Protocol string               `json:"protocol"`
	ID       string               `json:"id,omitempty"`
	OK       bool                 `json:"ok"`
	Status   string               `json:"status,omitempty"`
	Profiles []ProfileDescription `json:"profiles,omitempty"`
	Lease    *Delivery            `json:"lease,omitempty"`
	Error    *ProtocolError       `json:"error,omitempty"`
}

type ProtocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Server struct {
	Broker          *Broker
	MaxMessageBytes int
	CleanupTimeout  time.Duration
}

// Serve exchanges one JSON object per line. The caller must keep stdin open
// for the lifetime of any returned lease. EOF, context cancellation, or a
// transport error revokes every outstanding lease before Serve returns.
func (s Server) Serve(ctx context.Context, input io.Reader, output io.Writer) (serveErr error) {
	if s.Broker == nil {
		return clerr.New(clerr.RuntimeUnavailable, "sandbox plugin broker is required")
	}
	if input == nil || output == nil {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin input and output are required")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), s.cleanupTimeout())
		defer cancel()
		serveErr = errors.Join(serveErr, s.Broker.CloseAll(cleanupCtx))
	}()

	lines := make(chan scanResult, 1)
	go scanProtocolLines(ctx, input, s.maxMessageBytes(), lines)
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)

	for {
		select {
		case <-ctx.Done():
			return nil
		case scanned := <-lines:
			if scanned.done {
				return scanned.err
			}
			response := s.handle(ctx, scanned.line)
			if err := encoder.Encode(response); err != nil {
				return clerr.Wrap(clerr.RuntimeUnavailable, "write sandbox plugin response", err)
			}
		}
	}
}

func (s Server) handle(ctx context.Context, line []byte) ProtocolResponse {
	request, err := decodeRequest(line)
	if err != nil {
		return errorResponse("", err)
	}
	if request.Protocol != ProtocolVersion {
		return errorResponse(request.ID, clerr.New(clerr.ConfigInvalid, "sandbox plugin protocol version is unsupported"))
	}
	if !validRequestID(request.ID) {
		return errorResponse("", clerr.New(clerr.ConfigInvalid, "sandbox plugin request id is invalid"))
	}

	switch request.Method {
	case "ping":
		if request.payloadCount() != 0 {
			return errorResponse(request.ID, clerr.New(clerr.ConfigInvalid, "sandbox plugin ping must not include a method payload"))
		}
		return ProtocolResponse{Protocol: ProtocolVersion, ID: request.ID, OK: true, Status: "ready"}
	case "describe":
		if request.Describe == nil || request.payloadCount() != 1 {
			return errorResponse(request.ID, clerr.New(clerr.ConfigInvalid, "sandbox plugin describe payload is required"))
		}
		profiles, err := s.Broker.Describe(ctx, *request.Describe)
		if err != nil {
			return errorResponse(request.ID, err)
		}
		return ProtocolResponse{Protocol: ProtocolVersion, ID: request.ID, OK: true, Profiles: profiles}
	case "open":
		if request.Open == nil || request.payloadCount() != 1 {
			return errorResponse(request.ID, clerr.New(clerr.ConfigInvalid, "sandbox plugin open payload is required"))
		}
		lease, err := s.Broker.Open(ctx, *request.Open)
		if err != nil {
			return errorResponse(request.ID, err)
		}
		return ProtocolResponse{Protocol: ProtocolVersion, ID: request.ID, OK: true, Lease: &lease}
	case "close":
		if request.Close == nil || request.payloadCount() != 1 || strings.TrimSpace(request.Close.LeaseID) == "" {
			return errorResponse(request.ID, clerr.New(clerr.ConfigInvalid, "sandbox plugin close lease id is required"))
		}
		if err := s.Broker.Close(ctx, request.Close.LeaseID); err != nil {
			return errorResponse(request.ID, err)
		}
		return ProtocolResponse{Protocol: ProtocolVersion, ID: request.ID, OK: true, Status: "closed"}
	default:
		return errorResponse(request.ID, clerr.New(clerr.ConfigInvalid, "sandbox plugin method is unsupported"))
	}
}

func (r ProtocolRequest) payloadCount() int {
	count := 0
	if r.Describe != nil {
		count++
	}
	if r.Open != nil {
		count++
	}
	if r.Close != nil {
		count++
	}
	return count
}

type scanResult struct {
	line []byte
	err  error
	done bool
}

func scanProtocolLines(ctx context.Context, input io.Reader, maxBytes int, results chan<- scanResult) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxBytes)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		select {
		case results <- scanResult{line: line}:
		case <-ctx.Done():
			return
		}
	}
	result := scanResult{done: true}
	if err := scanner.Err(); err != nil {
		result.err = clerr.Wrap(clerr.ConfigInvalid, "read sandbox plugin request", redactedScanError{err: err})
	}
	select {
	case results <- result:
	case <-ctx.Done():
	}
}

func decodeRequest(line []byte) (ProtocolRequest, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return ProtocolRequest{}, clerr.New(clerr.ConfigInvalid, "sandbox plugin request is empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var request ProtocolRequest
	if err := decoder.Decode(&request); err != nil {
		return ProtocolRequest{}, clerr.New(clerr.ConfigInvalid, "sandbox plugin request is invalid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ProtocolRequest{}, clerr.New(clerr.ConfigInvalid, "sandbox plugin request must contain one JSON object")
	}
	return request, nil
}

func errorResponse(id string, err error) ProtocolResponse {
	code := clerr.RuntimeUnavailable
	message := "sandbox plugin request failed"
	if typedCode, ok := clerr.CodeOf(err); ok {
		code = typedCode
		message = err.Error()
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		message = "sandbox plugin request was canceled"
	}
	return ProtocolResponse{
		Protocol: ProtocolVersion,
		ID:       id,
		OK:       false,
		Error: &ProtocolError{
			Code:    string(code),
			Message: message,
		},
	}
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validRequestID(id string) bool {
	return requestIDPattern.MatchString(id)
}

func (s Server) maxMessageBytes() int {
	if s.MaxMessageBytes > 0 {
		return s.MaxMessageBytes
	}
	return defaultMaxMessageBytes
}

func (s Server) cleanupTimeout() time.Duration {
	if s.CleanupTimeout > 0 {
		return s.CleanupTimeout
	}
	return defaultCleanupTimeout
}

type redactedScanError struct {
	err error
}

func (e redactedScanError) Error() string {
	return fmt.Sprintf("protocol input rejected (%T)", e.err)
}
