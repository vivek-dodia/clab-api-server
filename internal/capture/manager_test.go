package capture

import (
	"strings"
	"testing"
)

func TestParseExtraEnvVars(t *testing.T) {
	parsed := parseExtraEnvVars("HTTP_PROXY=http://proxy, http_proxy=http://proxy2,EMPTY=,MALFORMED")

	if got := parsed["HTTP_PROXY"]; got != "http://proxy" {
		t.Fatalf("unexpected HTTP_PROXY value: %q", got)
	}
	if got := parsed["http_proxy"]; got != "http://proxy2" {
		t.Fatalf("unexpected http_proxy value: %q", got)
	}
	if got := parsed["EMPTY"]; got != "" {
		t.Fatalf("unexpected EMPTY value: %q", got)
	}
	if got := parsed["MALFORMED"]; got != "" {
		t.Fatalf("unexpected MALFORMED value: %q", got)
	}
}

func TestInjectComposeEnvironment(t *testing.T) {
	input := []byte(`
services:
  gostwire:
    image: example
  edgeshark:
    image: example
`)

	output, err := injectComposeEnvironment(input, map[string]string{
		"HTTP_PROXY": "http://proxy",
	})
	if err != nil {
		t.Fatalf("injectComposeEnvironment returned error: %v", err)
	}

	text := string(output)
	if !strings.Contains(text, "HTTP_PROXY=http://proxy") {
		t.Fatalf("expected injected env var in output, got:\n%s", text)
	}
}

func TestBuildPacketflixURI(t *testing.T) {
	uri := buildPacketflixURI("localhost", 5001, "clab-lab-srl1", []string{"e1-1", "e1-2"})

	if !strings.HasPrefix(uri, "packetflix:ws://localhost:5001/capture?") {
		t.Fatalf("unexpected prefix: %s", uri)
	}
	if !strings.Contains(uri, "nif=e1-1%2Fe1-2") {
		t.Fatalf("expected encoded nif list in URI: %s", uri)
	}
}
