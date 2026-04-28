package serverversion

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	RepoURL              = "https://github.com/srl-labs/clab-api-server"
	LatestReleaseURL     = RepoURL + "/releases/latest"
	DefaultInstallScript = "https://raw.githubusercontent.com/srl-labs/clab-api-server/main/install.sh"
)

const checkTimeout = 5 * time.Second

var releaseTagPattern = regexp.MustCompile(`^clab-(v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)-api-(v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$`)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type CheckOptions struct {
	FetchLatestVersion func(context.Context) (string, error)
}

type UpgradeOptions struct {
	InstallScriptURL string
	Download         func(context.Context, string, io.Writer) error
	RunCommand       func(context.Context, string, []string, []string, io.Writer, io.Writer) error
	IsRoot           func() bool
	Environ          func() []string
	Stdout           io.Writer
	Stderr           io.Writer
}

func FormatInfo(info BuildInfo) string {
	lines := []string{
		fmt.Sprintf("version: %s", info.Version),
		fmt.Sprintf("commit: %s", info.Commit),
		fmt.Sprintf("built: %s", info.Date),
		fmt.Sprintf("source: %s", RepoURL),
		fmt.Sprintf("latest: %s", LatestReleaseURL),
	}

	return strings.Join(lines, "\n")
}

func Check(ctx context.Context, currentVersion string, opts CheckOptions) (string, error) {
	if VersionCheckDisabled() {
		return "Version check disabled via CLAB_VERSION_CHECK", nil
	}

	fetchLatest := opts.FetchLatestVersion
	if fetchLatest == nil {
		fetchLatest = FetchLatestVersion
	}

	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	latestVersion, err := fetchLatest(ctx)
	if err != nil {
		return "", err
	}

	if cmp, ok := CompareReleaseVersions(currentVersion, latestVersion); ok {
		switch {
		case cmp < 0:
			return FormatNewVersionMessage(latestVersion), nil
		case cmp == 0:
			return fmt.Sprintf("You are on the latest clab-api-server version (%s)", currentVersion), nil
		default:
			return fmt.Sprintf("You are on a newer clab-api-server version (%s) than the latest release (%s)", currentVersion, latestVersion), nil
		}
	}

	return fmt.Sprintf("Latest clab-api-server version: %s (current: %s)", latestVersion, currentVersion), nil
}

func VersionCheckDisabled() bool {
	return strings.Contains(strings.ToLower(os.Getenv("CLAB_VERSION_CHECK")), "disable")
}

func FetchLatestVersion(ctx context.Context) (string, error) {
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, LatestReleaseURL, http.NoBody)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", fmt.Errorf("no response while fetching latest clab-api-server release")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	return ParseLatestReleaseLocation(resp.Header.Get("Location"))
}

func ParseLatestReleaseLocation(location string) (string, error) {
	location = strings.TrimSpace(location)
	if location == "" {
		return "", fmt.Errorf("latest release redirect location missing")
	}

	parts := strings.Split(location, "/releases/tag/")
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected latest release location %q", location)
	}

	tag := strings.SplitN(parts[1], "?", 2)[0]
	tag = strings.SplitN(tag, "#", 2)[0]
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "", fmt.Errorf("latest release tag missing")
	}

	return tag, nil
}

func CompareReleaseVersions(currentVersion, latestVersion string) (int, bool) {
	currentRelease, currentOK := parseReleaseTag(currentVersion)
	latestRelease, latestOK := parseReleaseTag(latestVersion)
	if currentOK && latestOK {
		if cmp := semver.Compare(currentRelease.api, latestRelease.api); cmp != 0 {
			return cmp, true
		}

		return semver.Compare(currentRelease.clab, latestRelease.clab), true
	}

	currentSemver, currentOK := normalizeSemver(currentVersion)
	latestSemver, latestOK := normalizeSemver(latestVersion)
	if currentOK && latestOK {
		return semver.Compare(currentSemver, latestSemver), true
	}

	return 0, false
}

func FormatNewVersionMessage(latestVersion string) string {
	return fmt.Sprintf(
		"A newer clab-api-server version (%s) is available!\nRelease: %s/releases/tag/%s\nRun 'sudo clab-api-server version upgrade' to upgrade.",
		latestVersion,
		RepoURL,
		latestVersion,
	)
}

func Upgrade(ctx context.Context, opts UpgradeOptions) error {
	installScriptURL := opts.InstallScriptURL
	if installScriptURL == "" {
		installScriptURL = DefaultInstallScript
	}

	download := opts.Download
	if download == nil {
		download = DownloadURL
	}

	runCommand := opts.RunCommand
	if runCommand == nil {
		runCommand = RunCommand
	}

	isRoot := opts.IsRoot
	if isRoot == nil {
		isRoot = func() bool {
			return os.Geteuid() == 0
		}
	}

	environ := opts.Environ
	if environ == nil {
		environ = os.Environ
	}

	stdout := opts.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}

	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	f, err := os.CreateTemp("", "clab-api-server-install-")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		_ = os.Remove(f.Name())
	}()

	if err := download(ctx, installScriptURL, f); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to download upgrade script: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close upgrade script: %w", err)
	}

	name := "bash"
	args := []string{f.Name(), "upgrade"}
	if !isRoot() {
		name = "sudo"
		args = []string{"-E", "bash", f.Name(), "upgrade"}
	}

	if err := runCommand(ctx, name, args, environ(), stdout, stderr); err != nil {
		return fmt.Errorf("upgrade failed: %w", err)
	}

	return nil
}

func DownloadURL(ctx context.Context, url string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("no response while downloading %s", url)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unexpected status %s while downloading %s", resp.Status, url)
	}

	_, err = io.Copy(w, resp.Body)
	return err
}

func RunCommand(ctx context.Context, name string, args []string, env []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return cmd.Run()
}

type releaseVersion struct {
	clab string
	api  string
}

func parseReleaseTag(tag string) (releaseVersion, bool) {
	matches := releaseTagPattern.FindStringSubmatch(strings.TrimSpace(tag))
	if matches == nil {
		return releaseVersion{}, false
	}

	clabVersion, ok := normalizeSemver(matches[1])
	if !ok {
		return releaseVersion{}, false
	}

	apiVersion, ok := normalizeSemver(matches[2])
	if !ok {
		return releaseVersion{}, false
	}

	return releaseVersion{
		clab: clabVersion,
		api:  apiVersion,
	}, true
}

func normalizeSemver(version string) (string, bool) {
	v := strings.TrimSpace(version)
	if v == "" {
		return "", false
	}

	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}

	if !semver.IsValid(v) {
		return "", false
	}

	return v, true
}
