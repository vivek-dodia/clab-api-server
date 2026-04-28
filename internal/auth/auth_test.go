package auth

import (
	"testing"
	"time"
)

func TestResolveLoginDuration(t *testing.T) {
	t.Parallel()

	defaultDuration := 24 * time.Hour

	tests := []struct {
		name      string
		requested string
		expected  time.Duration
		expectErr bool
	}{
		{
			name:      "defaults to configured lifetime",
			requested: "",
			expected:  defaultDuration,
		},
		{
			name:      "supports day suffix",
			requested: "7d",
			expected:  7 * 24 * time.Hour,
		},
		{
			name:      "supports compound go duration",
			requested: "1h30m",
			expected:  90 * time.Minute,
		},
		{
			name:      "supports decimal day suffix",
			requested: "1.5d",
			expected:  36 * time.Hour,
		},
		{
			name:      "supports week suffix",
			requested: "2w",
			expected:  14 * 24 * time.Hour,
		},
		{
			name:      "rejects invalid input",
			requested: "forever",
			expectErr: true,
		},
		{
			name:      "rejects non-positive durations",
			requested: "0h",
			expectErr: true,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			actual, err := ResolveLoginDuration(testCase.requested, defaultDuration)
			if testCase.expectErr {
				if err == nil {
					t.Fatalf("expected an error for %q", testCase.requested)
				}
				return
			}

			if err != nil {
				t.Fatalf("ResolveLoginDuration(%q) returned error: %v", testCase.requested, err)
			}

			if actual != testCase.expected {
				t.Fatalf("ResolveLoginDuration(%q) = %s, want %s", testCase.requested, actual, testCase.expected)
			}
		})
	}
}
