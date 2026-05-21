package api

import (
	"testing"

	"github.com/srl-labs/clab-api-server/internal/models"
)

func TestDefaultCustomNodesUseDashedSRLinuxType(t *testing.T) {
	nodes := defaultCustomNodes()
	if len(nodes) == 0 {
		t.Fatal("expected default custom nodes")
	}

	if got := customNodeString(nodes[0], "type"); got != "ixr-d1" {
		t.Fatalf("expected SR Linux default type ixr-d1, got %q", got)
	}
}

func TestNormalizeCustomNodesRewritesDeprecatedSRLinuxTypes(t *testing.T) {
	nodes := normalizeCustomNodes([]models.CustomNodeTemplate{
		{
			"name": "SR Linux",
			"kind": "nokia_srlinux",
			"type": "ixrd1",
		},
		{
			"name": "Linux",
			"kind": "linux",
			"type": "ixrd1",
		},
	})

	if got := customNodeString(nodes[0], "type"); got != "ixr-d1" {
		t.Fatalf("expected deprecated SR Linux type to normalize to ixr-d1, got %q", got)
	}
	if got := customNodeString(nodes[1], "type"); got != "ixrd1" {
		t.Fatalf("expected non-SR Linux type to remain untouched, got %q", got)
	}
}
