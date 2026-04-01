package terminal

import (
	"strings"
	"testing"

	"github.com/srl-labs/clab-api-server/internal/models"
)

func TestResolveLaunchCommandShellAllowlist(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolShell, CreateSessionOptions{
		Runtime:       "docker",
		ContainerID:   "cid-123",
		ContainerKind: "nokia_srlinux",
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	expected := []string{"docker", "exec", "-it", "cid-123", "sr_cli"}
	if strings.Join(command, " ") != strings.Join(expected, " ") {
		t.Fatalf("unexpected shell command: got %v want %v", command, expected)
	}
}

func TestResolveLaunchCommandFallbackShell(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolShell, CreateSessionOptions{
		Runtime:       "podman",
		ContainerID:   "cid-456",
		ContainerKind: "unknown-kind",
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	expected := []string{"podman", "exec", "-it", "cid-456", "sh"}
	if strings.Join(command, " ") != strings.Join(expected, " ") {
		t.Fatalf("unexpected fallback shell command: got %v want %v", command, expected)
	}
}

func TestResolveLaunchCommandSSHUsesDirectArgv(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolSSH, CreateSessionOptions{
		ContainerIP:   "172.20.20.2/24",
		ContainerKind: "cisco_xrd",
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	if len(command) == 0 || command[0] != "ssh" {
		t.Fatalf("expected ssh binary, got %v", command)
	}
	for _, disallowed := range []string{"sh", "bash", "-lc", "-c"} {
		for _, part := range command {
			if part == disallowed {
				t.Fatalf("unexpected shell wrapper token %q in %v", disallowed, command)
			}
		}
	}
	if last := command[len(command)-1]; last != "clab@172.20.20.2" {
		t.Fatalf("unexpected ssh target %q", last)
	}
}

func TestResolveLaunchCommandTelnetUsesDirectArgv(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolTelnet, CreateSessionOptions{
		Runtime:     "docker",
		ContainerID: "cid-789",
		TelnetPort:  7001,
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	expected := []string{"docker", "exec", "-it", "cid-789", "telnet", "127.0.0.1", "7001"}
	if strings.Join(command, " ") != strings.Join(expected, " ") {
		t.Fatalf("unexpected telnet command: got %v want %v", command, expected)
	}
	for _, disallowed := range []string{"ssh", "sh", "bash", "-lc", "-c"} {
		for _, part := range command {
			if part == disallowed {
				t.Fatalf("unexpected shell/ssh wrapper token %q in %v", disallowed, command)
			}
		}
	}
}

func TestResolveLaunchCommandTelnetDefaultsPort(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolTelnet, CreateSessionOptions{
		Runtime:     "podman",
		ContainerID: "cid-999",
		TelnetPort:  0,
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	expected := []string{"podman", "exec", "-it", "cid-999", "telnet", "127.0.0.1", "5000"}
	if strings.Join(command, " ") != strings.Join(expected, " ") {
		t.Fatalf("unexpected default telnet command: got %v want %v", command, expected)
	}
}

func TestSanitizeTerminalSizeClampsInvalidValues(t *testing.T) {
	cols, rows := sanitizeTerminalSize(0, 500)
	if cols != DefaultTerminalCols {
		t.Fatalf("unexpected cols: got %d want %d", cols, DefaultTerminalCols)
	}
	if rows != DefaultTerminalRows {
		t.Fatalf("unexpected rows: got %d want %d", rows, DefaultTerminalRows)
	}
}
