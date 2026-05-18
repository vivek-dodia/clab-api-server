package api

import "testing"

func TestStripContainerPrefixHandlesResolvedAndUnresolvedPrefixes(t *testing.T) {
	labName := "srl-mirroring-lab"

	tests := map[string]string{
		"clab-srl-mirroring-lab-leaf2":              "leaf2",
		"srl-mirroring-lab-leaf2":                   "leaf2",
		"custom-srl-mirroring-lab-leaf2":            "leaf2",
		`${LAB_PREFIX:-""}-srl-mirroring-lab-leaf2`: "leaf2",
		"leaf2": "leaf2",
	}

	for input, want := range tests {
		if got := stripContainerPrefix(labName, input); got != want {
			t.Fatalf("stripContainerPrefix(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestScoreNodeMatchHandlesUnresolvedTopologyPrefix(t *testing.T) {
	labName := "srl-mirroring-lab"
	requested := `${LAB_PREFIX:-""}-srl-mirroring-lab-leaf2`

	tests := []string{
		"clab-srl-mirroring-lab-leaf2",
		"srl-mirroring-lab-leaf2",
		"custom-srl-mirroring-lab-leaf2",
		"leaf2",
	}

	for _, containerName := range tests {
		if score := scoreNodeMatch(labName, containerName, requested); score == 0 {
			t.Fatalf("scoreNodeMatch(%q, %q, %q) = 0, want a match", labName, containerName, requested)
		}
	}
}

func TestHasDifferentDefaultContainerlabPrefix(t *testing.T) {
	labName := "srl-mirroring-lab"

	tests := map[string]bool{
		"clab-srl-mirroring-lab-leaf2":              false,
		"leaf2":                                     false,
		"clab-otherlab-leaf2":                       true,
		"custom-srl-mirroring-lab-leaf2":            false,
		`${LAB_PREFIX:-""}-srl-mirroring-lab-leaf2`: false,
	}

	for input, want := range tests {
		if got := hasDifferentDefaultContainerlabPrefix(labName, input); got != want {
			t.Fatalf("hasDifferentDefaultContainerlabPrefix(%q, %q) = %t, want %t", labName, input, got, want)
		}
	}
}
