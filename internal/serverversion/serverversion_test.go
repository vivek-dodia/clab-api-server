package serverversion

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestParseLatestReleaseLocation(t *testing.T) {
	got, err := ParseLatestReleaseLocation("https://github.com/srl-labs/clab-api-server/releases/tag/clab-0.74.1-api-0.2.2?expanded=true")
	if err != nil {
		t.Fatalf("ParseLatestReleaseLocation() returned error: %v", err)
	}

	if got != "clab-0.74.1-api-0.2.2" {
		t.Fatalf("ParseLatestReleaseLocation() = %q, want %q", got, "clab-0.74.1-api-0.2.2")
	}
}

func TestCompareReleaseVersionsUsesAPIServerVersionFirst(t *testing.T) {
	got, ok := CompareReleaseVersions("clab-0.75.0-api-0.2.1", "clab-0.74.1-api-0.2.2")
	if !ok {
		t.Fatal("CompareReleaseVersions() did not parse release tags")
	}

	if got >= 0 {
		t.Fatalf("CompareReleaseVersions() = %d, want current to be older because API version is lower", got)
	}
}

func TestCheckDisabledDoesNotFetchLatestVersion(t *testing.T) {
	t.Setenv("CLAB_VERSION_CHECK", "disable")

	got, err := Check(context.Background(), "clab-0.74.1-api-0.2.2", CheckOptions{
		FetchLatestVersion: func(context.Context) (string, error) {
			t.Fatal("FetchLatestVersion should not be called when version checks are disabled")
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("Check() returned error: %v", err)
	}

	if got != "Version check disabled via CLAB_VERSION_CHECK" {
		t.Fatalf("Check() = %q", got)
	}
}

func TestCheckReportsNewerVersion(t *testing.T) {
	got, err := Check(context.Background(), "clab-0.74.1-api-0.2.1", CheckOptions{
		FetchLatestVersion: func(context.Context) (string, error) {
			return "clab-0.74.1-api-0.2.2", nil
		},
	})
	if err != nil {
		t.Fatalf("Check() returned error: %v", err)
	}

	if !strings.Contains(got, "A newer clab-api-server version (clab-0.74.1-api-0.2.2) is available!") {
		t.Fatalf("Check() = %q", got)
	}
	if !strings.Contains(got, "sudo clab-api-server version upgrade") {
		t.Fatalf("Check() should include upgrade instruction, got %q", got)
	}
}

func TestCheckReportsLatestForEqualVersions(t *testing.T) {
	got, err := Check(context.Background(), "clab-0.74.1-api-0.2.2", CheckOptions{
		FetchLatestVersion: func(context.Context) (string, error) {
			return "clab-0.74.1-api-0.2.2", nil
		},
	})
	if err != nil {
		t.Fatalf("Check() returned error: %v", err)
	}

	if got != "You are on the latest clab-api-server version (clab-0.74.1-api-0.2.2)" {
		t.Fatalf("Check() = %q", got)
	}
}

func TestCheckFallsBackForUnparseableCurrentVersion(t *testing.T) {
	got, err := Check(context.Background(), "development", CheckOptions{
		FetchLatestVersion: func(context.Context) (string, error) {
			return "clab-0.74.1-api-0.2.2", nil
		},
	})
	if err != nil {
		t.Fatalf("Check() returned error: %v", err)
	}

	want := "Latest clab-api-server version: clab-0.74.1-api-0.2.2 (current: development)"
	if got != want {
		t.Fatalf("Check() = %q, want %q", got, want)
	}
}

func TestUpgradeRunsInstallScriptWithSudoWhenNotRoot(t *testing.T) {
	var gotName string
	var gotArgs []string
	var gotEnv []string

	err := Upgrade(context.Background(), UpgradeOptions{
		InstallScriptURL: "https://example.invalid/install.sh",
		Download: func(_ context.Context, url string, w io.Writer) error {
			if url != "https://example.invalid/install.sh" {
				t.Fatalf("download url = %q", url)
			}
			_, err := io.WriteString(w, "#!/usr/bin/env bash\n")
			return err
		},
		RunCommand: func(_ context.Context, name string, args []string, env []string, _ io.Writer, _ io.Writer) error {
			gotName = name
			gotArgs = append([]string(nil), args...)
			gotEnv = append([]string(nil), env...)
			return nil
		},
		IsRoot:  func() bool { return false },
		Environ: func() []string { return []string{"GITHUB_TOKEN=test"} },
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Upgrade() returned error: %v", err)
	}

	if gotName != "sudo" {
		t.Fatalf("command name = %q, want sudo", gotName)
	}
	if len(gotArgs) != 4 || gotArgs[0] != "-E" || gotArgs[1] != "bash" || gotArgs[3] != "upgrade" {
		t.Fatalf("command args = %#v, want sudo -E bash <tempfile> upgrade", gotArgs)
	}
	if len(gotEnv) != 1 || gotEnv[0] != "GITHUB_TOKEN=test" {
		t.Fatalf("command env = %#v", gotEnv)
	}
}

func TestUpgradeRunsInstallScriptDirectlyWhenRoot(t *testing.T) {
	var gotName string
	var gotArgs []string

	err := Upgrade(context.Background(), UpgradeOptions{
		Download: func(_ context.Context, _ string, w io.Writer) error {
			_, err := io.WriteString(w, "#!/usr/bin/env bash\n")
			return err
		},
		RunCommand: func(_ context.Context, name string, args []string, _ []string, _ io.Writer, _ io.Writer) error {
			gotName = name
			gotArgs = append([]string(nil), args...)
			return nil
		},
		IsRoot: func() bool { return true },
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Upgrade() returned error: %v", err)
	}

	if gotName != "bash" {
		t.Fatalf("command name = %q, want bash", gotName)
	}
	if len(gotArgs) != 2 || gotArgs[1] != "upgrade" {
		t.Fatalf("command args = %#v, want bash <tempfile> upgrade", gotArgs)
	}
}

func TestUpgradeWrapsRunnerError(t *testing.T) {
	err := Upgrade(context.Background(), UpgradeOptions{
		Download: func(_ context.Context, _ string, w io.Writer) error {
			_, writeErr := io.WriteString(w, "#!/usr/bin/env bash\n")
			return writeErr
		},
		RunCommand: func(context.Context, string, []string, []string, io.Writer, io.Writer) error {
			return errors.New("boom")
		},
		IsRoot: func() bool { return true },
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "upgrade failed: boom") {
		t.Fatalf("Upgrade() error = %v", err)
	}
}
