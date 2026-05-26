package clab

import (
	"errors"
	"os"
	"os/user"
	"testing"

	gotc "github.com/florianl/go-tc"
	clabcore "github.com/srl-labs/containerlab/core"
)

func TestNewContainerLabForOwnerSetsOwnerEnvDuringInit(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	if err := os.Setenv("SUDO_USER", "root-sudo"); err != nil {
		t.Fatalf("set SUDO_USER: %v", err)
	}
	if err := os.Setenv("USER", "root-user"); err != nil {
		t.Fatalf("set USER: %v", err)
	}

	sentinelErr := errors.New("stop after env assertion")
	var gotSudoUser string
	var gotUser string
	_, err := newContainerLabForOwner("test", func(_ *clabcore.CLab) error {
		gotSudoUser = os.Getenv("SUDO_USER")
		gotUser = os.Getenv("USER")
		return sentinelErr
	})
	if !errors.Is(err, sentinelErr) {
		t.Fatalf("newContainerLabForOwner error = %v, want %v", err, sentinelErr)
	}
	if gotSudoUser != "test" {
		t.Fatalf("SUDO_USER during init = %q, want %q", gotSudoUser, "test")
	}
	if gotUser != "test" {
		t.Fatalf("USER during init = %q, want %q", gotUser, "test")
	}
	if got := os.Getenv("SUDO_USER"); got != "root-sudo" {
		t.Fatalf("restored SUDO_USER = %q, want %q", got, "root-sudo")
	}
	if got := os.Getenv("USER"); got != "root-user" {
		t.Fatalf("restored USER = %q, want %q", got, "root-user")
	}
}

func TestSetProcessOwnerEnvRestoresExistingValues(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	if err := os.Setenv("SUDO_USER", "root-sudo"); err != nil {
		t.Fatalf("set SUDO_USER: %v", err)
	}
	if err := os.Setenv("USER", "root-user"); err != nil {
		t.Fatalf("set USER: %v", err)
	}

	restoreOwnerEnv := setProcessOwnerEnv("test")
	if got := os.Getenv("SUDO_USER"); got != "test" {
		t.Fatalf("SUDO_USER = %q, want %q", got, "test")
	}
	if got := os.Getenv("USER"); got != "test" {
		t.Fatalf("USER = %q, want %q", got, "test")
	}

	restoreOwnerEnv()
	if got := os.Getenv("SUDO_USER"); got != "root-sudo" {
		t.Fatalf("restored SUDO_USER = %q, want %q", got, "root-sudo")
	}
	if got := os.Getenv("USER"); got != "root-user" {
		t.Fatalf("restored USER = %q, want %q", got, "root-user")
	}
}

func TestSetProcessOwnerEnvRestoresUnsetValues(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	_ = os.Unsetenv("SUDO_USER")
	_ = os.Unsetenv("USER")

	restoreOwnerEnv := setProcessOwnerEnv("test")
	if got := os.Getenv("SUDO_USER"); got != "test" {
		t.Fatalf("SUDO_USER = %q, want %q", got, "test")
	}
	if got := os.Getenv("USER"); got != "test" {
		t.Fatalf("USER = %q, want %q", got, "test")
	}

	restoreOwnerEnv()
	if _, ok := os.LookupEnv("SUDO_USER"); ok {
		t.Fatalf("SUDO_USER remained set after restore")
	}
	if _, ok := os.LookupEnv("USER"); ok {
		t.Fatalf("USER remained set after restore")
	}
}

func TestSetProcessOwnerEnvSetsSudoIDsForExistingUser(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	current, err := user.Current()
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}

	restoreOwnerEnv := setProcessOwnerEnv(current.Username)
	defer restoreOwnerEnv()

	if got := os.Getenv("SUDO_UID"); got != current.Uid {
		t.Fatalf("SUDO_UID = %q, want %q", got, current.Uid)
	}
	if got := os.Getenv("SUDO_GID"); got != current.Gid {
		t.Fatalf("SUDO_GID = %q, want %q", got, current.Gid)
	}
}

func TestHasNetemQdisc(t *testing.T) {
	qdiscs := []gotc.Object{
		{Msg: gotc.Msg{Ifindex: 10}, Attribute: gotc.Attribute{Kind: "fq_codel"}},
		{Msg: gotc.Msg{Ifindex: 11}, Attribute: gotc.Attribute{Kind: "netem"}},
	}

	if !hasNetemQdisc(qdiscs, 11) {
		t.Fatalf("expected netem qdisc on interface index 11")
	}
	if hasNetemQdisc(qdiscs, 10) {
		t.Fatalf("did not expect non-netem qdisc on interface index 10 to match")
	}
	if hasNetemQdisc(qdiscs, 12) {
		t.Fatalf("did not expect missing interface index to match")
	}
}

func TestIsNetemAlreadyClearError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "invalid argument", err: errors.New("netlink receive: invalid argument"), want: true},
		{name: "not found", err: errors.New("could not find qdisc for interface eth1"), want: true},
		{name: "other", err: errors.New("permission denied"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNetemAlreadyClearError(tc.err); got != tc.want {
				t.Fatalf("isNetemAlreadyClearError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func preserveEnv(keys ...string) func() {
	type envValue struct {
		value string
		set   bool
	}

	values := make(map[string]envValue, len(keys))
	for _, key := range keys {
		value, set := os.LookupEnv(key)
		values[key] = envValue{value: value, set: set}
	}

	return func() {
		for key, value := range values {
			if value.set {
				_ = os.Setenv(key, value.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}
}
