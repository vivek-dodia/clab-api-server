package clab

import (
	"encoding/json"
	"strings"
	"testing"

	clabcore "github.com/srl-labs/containerlab/core"
)

func TestApplyResultToResponseCopiesFields(t *testing.T) {
	result := &clabcore.ApplyResult{
		DryRun:           true,
		DeployedLab:      true,
		LabName:          "demo",
		AddedNodes:       []string{"n2"},
		DeletedNodes:     []string{"n3"},
		RecreatedNodes:   []string{"xrd1"},
		StartedNodes:     []string{"n4"},
		AddedLinks:       []string{"n1:eth1<-->n2:eth1"},
		DeletedEndpoints: []string{"n3:eth1"},
		RestartedNodes:   []string{"ceos1"},
		NodeChangeReasons: map[string]string{
			"ceos1": "added link",
		},
	}

	response := ApplyResultToResponse(result)

	if !response.DryRun {
		t.Fatal("expected dryRun=true")
	}
	if !response.DeployedLab {
		t.Fatal("expected deployedLab=true")
	}
	if response.LabName != "demo" {
		t.Fatalf("labName = %q, want demo", response.LabName)
	}
	if got := response.AddedNodes[0]; got != "n2" {
		t.Fatalf("addedNodes[0] = %q, want n2", got)
	}
	if got := response.NodeChangeReasons["ceos1"]; got != "added link" {
		t.Fatalf("nodeChangeReasons[ceos1] = %q, want added link", got)
	}

	result.AddedNodes[0] = "mutated"
	result.NodeChangeReasons["ceos1"] = "mutated"
	if got := response.AddedNodes[0]; got != "n2" {
		t.Fatalf("response addedNodes was aliased, got %q", got)
	}
	if got := response.NodeChangeReasons["ceos1"]; got != "added link" {
		t.Fatalf("response nodeChangeReasons was aliased, got %q", got)
	}
}

func TestApplyResultToResponseHandlesNil(t *testing.T) {
	response := ApplyResultToResponse(nil)
	if response.AddedNodes == nil {
		t.Fatal("expected non-nil addedNodes")
	}
	if response.NodeChangeReasons == nil {
		t.Fatal("expected non-nil nodeChangeReasons")
	}
}

func TestApplyResultToResponseHandlesNilFields(t *testing.T) {
	response := ApplyResultToResponse(&clabcore.ApplyResult{})
	if response.AddedNodes == nil {
		t.Fatal("expected non-nil addedNodes")
	}
	if response.DeletedEndpoints == nil {
		t.Fatal("expected non-nil deletedEndpoints")
	}
	if response.NodeChangeReasons == nil {
		t.Fatal("expected non-nil nodeChangeReasons")
	}
}

func TestApplyResultToResponseJSONUsesEmptyArrays(t *testing.T) {
	response := ApplyResultToResponse(&clabcore.ApplyResult{
		AddedNodes: []string{"srl3"},
	})

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	body := string(data)
	if strings.Contains(body, "null") {
		t.Fatalf("expected empty collections to marshal as arrays/maps, got %s", body)
	}

	for _, field := range []string{
		`"deletedNodes":[]`,
		`"recreatedNodes":[]`,
		`"startedNodes":[]`,
		`"addedLinks":[]`,
		`"deletedEndpoints":[]`,
		`"restartedNodes":[]`,
		`"nodeChangeReasons":{}`,
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("expected marshaled response to contain %s, got %s", field, body)
		}
	}
}
