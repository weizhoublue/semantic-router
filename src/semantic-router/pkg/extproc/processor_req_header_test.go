package extproc

import (
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	http_ext "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	ext_proc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/vllm-project/semantic-router/src/semantic-router/pkg/authz"
	"github.com/vllm-project/semantic-router/src/semantic-router/pkg/llmprotocol"
)

func newRequestHeaders(method, path string) *ext_proc.ProcessingRequest_RequestHeaders {
	return &ext_proc.ProcessingRequest_RequestHeaders{
		RequestHeaders: &ext_proc.HttpHeaders{
			Headers: &core.HeaderMap{Headers: []*core.HeaderValue{
				{Key: ":method", Value: method},
				{Key: ":path", Value: path},
			}},
		},
	}
}

func TestDetectSourceFormat(t *testing.T) {
	tests := []struct {
		path string
		want llmprotocol.WireFormat
	}{
		{path: "/v1/chat/completions", want: llmprotocol.OpenAIChatV1},
		{path: "/v1/responses", want: llmprotocol.OpenAIResponsesV1},
		{path: "/v1/responses?stream=true", want: llmprotocol.OpenAIResponsesV1},
		{path: "/v1/messages", want: llmprotocol.AnthropicMessagesV1},
		{path: "/v1/messages/count_tokens", want: llmprotocol.AnthropicMessagesV1},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			ctx := &RequestContext{}
			detectSourceFormat(test.path, ctx)
			if ctx.SourceFormat != test.want {
				t.Fatalf("source format = %q, want %q", ctx.SourceFormat, test.want)
			}
		})
	}
}

func TestApplyHeaderPassThroughPolicyDropsOnlyTransportHeaders(t *testing.T) {
	ctx := &RequestContext{Headers: map[string]string{
		"host":              "example.test",
		"content-length":    "42",
		"connection":        "keep-alive",
		"transfer-encoding": "chunked",
		"anthropic-version": "2024-10-22",
		"x-application":     "kept",
	}}
	applyHeaderPassThroughPolicy(ctx)
	for _, key := range []string{"host", "content-length", "connection", "transfer-encoding"} {
		if _, found := ctx.Headers[key]; found {
			t.Fatalf("transport header %q was retained", key)
		}
	}
	for _, key := range []string{"anthropic-version", "x-application"} {
		if _, found := ctx.Headers[key]; !found {
			t.Fatalf("application header %q was removed", key)
		}
	}
	applyHeaderPassThroughPolicy(nil)
}

func TestHandleRequestHeadersRemovesInjectedCredentialsBeforeFullDuplexForwarding(t *testing.T) {
	const credentialHeader = "x-custom-openai-key"
	router := &OpenAIRouter{
		CredentialResolver: authz.NewCredentialResolver(
			authz.NewHeaderInjectionProvider(map[string]string{"openai": credentialHeader}),
		),
	}
	request := newRequestHeaders("POST", "/v1/chat/completions")
	request.RequestHeaders.Headers.Headers = append(
		request.RequestHeaders.Headers.Headers,
		&core.HeaderValue{Key: credentialHeader, Value: "sk-user-secret"},
	)
	ctx := &RequestContext{Headers: make(map[string]string)}
	stream := NewMockStream(nil)
	processingRequest := &ext_proc.ProcessingRequest{
		ProtocolConfig: &ext_proc.ProtocolConfiguration{
			RequestBodyMode: http_ext.ProcessingMode_FULL_DUPLEX_STREAMED,
		},
		Request: request,
	}

	if err := router.handleProcessRequest(stream, processingRequest, ctx); err != nil {
		t.Fatalf("handleProcessRequest() error = %v", err)
	}
	if len(stream.Responses) != 1 {
		t.Fatalf("response count = %d, want 1", len(stream.Responses))
	}
	response := stream.Responses[0]
	removed := response.GetRequestHeaders().GetResponse().GetHeaderMutation().GetRemoveHeaders()
	found := false
	for _, header := range removed {
		if header == credentialHeader {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("credential header was not removed before forwarding: %v", removed)
	}
	if !ctx.FullDuplexRequestBody {
		t.Fatal("full-duplex request mode was not negotiated")
	}
	if got := ctx.Headers[credentialHeader]; got != "sk-user-secret" {
		t.Fatalf("captured credential = %q, want it retained for provider resolution", got)
	}
}

func TestValidatePublicGenerationEndpoints(t *testing.T) {
	router := &OpenAIRouter{ResponseAPIFilter: NewResponseAPIFilter(NewMockResponseStore())}
	tests := []struct {
		method string
		path   string
		status typev3.StatusCode
	}{
		{method: "POST", path: "/v1/chat/completions"},
		{method: "POST", path: "/v1/responses"},
		{method: "POST", path: "/v1/messages"},
		{method: "GET", path: "/v1/messages", status: typev3.StatusCode_MethodNotAllowed},
		{method: "POST", path: "/v1/messages/count_tokens", status: typev3.StatusCode_NotFound},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			response := router.validateRequestHeaders(test.method, test.path)
			if test.status == 0 {
				if response != nil {
					t.Fatalf("valid generation endpoint returned immediate response: %+v", response)
				}
				return
			}
			if response == nil || response.GetImmediateResponse() == nil ||
				response.GetImmediateResponse().GetStatus().GetCode() != test.status {
				t.Fatalf("status = %+v, want %s", response, test.status)
			}
		})
	}
}

func TestResponseObjectPathParsing(t *testing.T) {
	if got := extractResponseIDFromPath("/v1/responses/resp_123?expand=true"); got != "resp_123" {
		t.Fatalf("response id = %q", got)
	}
	if got := extractResponseIDFromInputItemsPath("/v1/responses/resp_123/input_items"); got != "resp_123" {
		t.Fatalf("input-items response id = %q", got)
	}
	if got := extractResponseIDFromPath("/v1/responses/not-a-response"); got != "" {
		t.Fatalf("invalid response id = %q", got)
	}
}
