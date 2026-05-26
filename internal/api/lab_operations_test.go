package api

import "testing"

func TestLabOperationRegistryRejectsConcurrentOperation(t *testing.T) {
	registry := &labOperationRegistry{active: make(map[string]string)}

	release, active, ok := registry.begin("demo", "deploy")
	if !ok {
		t.Fatalf("first operation rejected with active %q", active)
	}

	_, active, ok = registry.begin("demo", "netem")
	if ok {
		t.Fatal("second operation on same lab was accepted")
	}
	if active != "deploy" {
		t.Fatalf("active operation = %q, want deploy", active)
	}

	release()
	release, active, ok = registry.begin("demo", "netem")
	if !ok {
		t.Fatalf("operation after release rejected with active %q", active)
	}
	release()
}

func TestLabOperationRegistryAllowsDifferentLabs(t *testing.T) {
	registry := &labOperationRegistry{active: make(map[string]string)}

	release, active, ok := registry.begin("demo-a", "deploy")
	if !ok {
		t.Fatalf("first operation rejected with active %q", active)
	}
	defer release()

	otherRelease, active, ok := registry.begin("demo-b", "destroy")
	if !ok {
		t.Fatalf("different lab operation rejected with active %q", active)
	}
	otherRelease()
}
