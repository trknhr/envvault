package sandboxplugin_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/sandboxplugin"
)

func TestStdioProtocolKeepsLeaseAliveUntilExplicitClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broker := testBroker(t)
	requestReader, requestWriter := io.Pipe()
	responseReader, responseWriter := io.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- (sandboxplugin.Server{Broker: broker}).Serve(ctx, requestReader, responseWriter)
	}()
	requests := json.NewEncoder(requestWriter)
	responses := bufio.NewReader(responseReader)

	if err := requests.Encode(sandboxplugin.ProtocolRequest{
		Protocol: sandboxplugin.ProtocolVersion,
		ID:       "request-1",
		Method:   "open",
		Open:     pointer(validRequest("openshell-sandbox-1")),
	}); err != nil {
		t.Fatalf("Encode(open) error = %v", err)
	}
	openLine, err := responses.ReadBytes('\n')
	if err != nil {
		t.Fatalf("ReadBytes(open) error = %v", err)
	}
	if strings.Contains(string(openLine), "secret-canary") {
		t.Fatal("protocol response leaked the upstream credential")
	}
	var opened sandboxplugin.ProtocolResponse
	if err := json.Unmarshal(openLine, &opened); err != nil {
		t.Fatalf("Unmarshal(open) error = %v", err)
	}
	if !opened.OK || opened.Lease == nil || opened.Lease.LeaseID == "" {
		t.Fatalf("open response = %#v", opened)
	}
	baseURL := opened.Lease.Environment["OPENAI_BASE_URL"]
	token := opened.Lease.Environment["OPENAI_API_KEY"]
	req, err := http.NewRequest(http.MethodPost, baseURL+"/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() while plugin session is open error = %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.StatusCode)
	}

	if _, err := io.WriteString(requestWriter, `{"protocol":"envvault.sandbox-plugin/v1","id":"request-2","method":"ping","unexpected":true}`+"\n"); err != nil {
		t.Fatalf("WriteString(invalid) error = %v", err)
	}
	invalidLine, err := responses.ReadBytes('\n')
	if err != nil {
		t.Fatalf("ReadBytes(invalid) error = %v", err)
	}
	var invalid sandboxplugin.ProtocolResponse
	if err := json.Unmarshal(invalidLine, &invalid); err != nil {
		t.Fatalf("Unmarshal(invalid) error = %v", err)
	}
	if invalid.OK || invalid.Error == nil || invalid.Error.Code != string(clerr.ConfigInvalid) {
		t.Fatalf("invalid response = %#v", invalid)
	}

	if err := requests.Encode(sandboxplugin.ProtocolRequest{
		Protocol: sandboxplugin.ProtocolVersion,
		ID:       "request-3",
		Method:   "close",
		Close:    &sandboxplugin.CloseRequest{LeaseID: opened.Lease.LeaseID},
	}); err != nil {
		t.Fatalf("Encode(close) error = %v", err)
	}
	closeLine, err := responses.ReadBytes('\n')
	if err != nil {
		t.Fatalf("ReadBytes(close) error = %v", err)
	}
	var closed sandboxplugin.ProtocolResponse
	if err := json.Unmarshal(closeLine, &closed); err != nil {
		t.Fatalf("Unmarshal(close) error = %v", err)
	}
	if !closed.OK || closed.Status != "closed" {
		t.Fatalf("close response = %#v", closed)
	}
	if connection, err := net.DialTimeout("tcp", opened.Lease.Egress[0].Address, 50*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("gateway remained reachable after protocol close")
	}

	if err := requestWriter.Close(); err != nil {
		t.Fatalf("Close(request writer) error = %v", err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop after protocol EOF")
	}
}

func TestStdioProtocolPing(t *testing.T) {
	broker := testBroker(t)
	input := strings.NewReader(`{"protocol":"envvault.sandbox-plugin/v1","id":"health-1","method":"ping"}` + "\n")
	var output strings.Builder

	if err := (sandboxplugin.Server{Broker: broker}).Serve(context.Background(), input, &output); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	var response sandboxplugin.ProtocolResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(output.String())), &response); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !response.OK || response.Status != "ready" || response.Protocol != sandboxplugin.ProtocolVersion {
		t.Fatalf("response = %#v", response)
	}
}

func TestStdioProtocolDescribe(t *testing.T) {
	broker := testBroker(t)
	request := sandboxplugin.ProtocolRequest{
		Protocol: sandboxplugin.ProtocolVersion,
		ID:       "describe-1",
		Method:   "describe",
		Describe: &sandboxplugin.DescribeRequest{Profiles: []string{"openai/codex"}},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal(request) error = %v", err)
	}
	var output strings.Builder

	if err := (sandboxplugin.Server{Broker: broker}).Serve(context.Background(), strings.NewReader(string(encoded)+"\n"), &output); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if strings.Contains(output.String(), "secret-canary") || strings.Contains(output.String(), "openai/key") {
		t.Fatal("describe response leaked credential data")
	}
	var response sandboxplugin.ProtocolResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(output.String())), &response); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !response.OK || len(response.Profiles) != 1 || response.Profiles[0].HTTP.AllowedPaths[0] != "/responses" {
		t.Fatalf("response = %#v", response)
	}
}

func pointer[T any](value T) *T {
	return &value
}
