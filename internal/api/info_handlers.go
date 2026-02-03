// internal/api/info_handlers.go
package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
	"golang.org/x/mod/semver"
)

const (
	containerlabModulePath          = "github.com/srl-labs/containerlab"
	containerlabRepoURL             = "https://github.com/srl-labs/containerlab"
	containerlabReleaseNotesBaseURL = "https://containerlab.dev/rn/"
	containerlabLatestReleaseURL    = "https://github.com/srl-labs/containerlab/releases/latest"
	containerlabInstallURL          = "https://containerlab.dev/install/"
	versionCheckTimeout             = 5 * time.Second
)

// @Summary Get containerlab version
// @Description Returns version information for the containerlab library in use.
// @Tags Version
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.VersionResponse "Containerlab version details"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/version [get]
func GetVersionHandler(c *gin.Context) {
	username := c.GetString("username") // For logging context
	log.Debugf("GetVersion user '%s': Requesting containerlab version info...", username)

	versionInfo, err := buildContainerlabVersionInfo()
	if err != nil {
		log.Error("GetVersion failed to resolve containerlab version", "user", username, "error", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("failed to determine containerlab version: %s", err.Error()),
		})
		return
	}

	log.Infof("GetVersion user '%s': Successfully retrieved containerlab version info.", username)
	c.JSON(http.StatusOK, models.VersionResponse{VersionInfo: versionInfo})
}

// @Summary Check containerlab updates
// @Description Checks whether a newer containerlab release is available.
// @Tags Version
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.VersionCheckResponse "Result of the version check"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Router /api/v1/version/check [get]
func CheckVersionHandler(c *gin.Context) {
	username := c.GetString("username") // For logging context
	log.Debugf("CheckVersion user '%s': Checking for containerlab updates...", username)

	ctx, cancel := context.WithTimeout(c.Request.Context(), versionCheckTimeout)
	defer cancel()

	result, err := buildContainerlabVersionCheckResult(ctx)
	if err != nil {
		log.Error("CheckVersion failed to check latest containerlab release", "user", username, "error", err)
		result = "Failed fetching latest version information"
	}

	c.JSON(http.StatusOK, models.VersionCheckResponse{
		CheckResult: result,
	})
}

func buildContainerlabVersionInfo() (string, error) {
	version, commit, date, ok := containerlabVersionDetails()
	if !ok {
		return "", fmt.Errorf("containerlab module version not found in build info")
	}

	lines := []string{
		fmt.Sprintf("version: %s", version),
		fmt.Sprintf("commit: %s", commit),
		fmt.Sprintf("date: %s", date),
		fmt.Sprintf("github: %s", containerlabRepoURL),
	}

	if releaseNotes := releaseNotesURL(version); releaseNotes != "" {
		lines = append(lines, fmt.Sprintf("release notes: %s", releaseNotes))
	}

	return strings.Join(lines, "\n"), nil
}

func containerlabVersionDetails() (string, string, string, bool) {
	moduleVersion, ok := containerlabModuleVersion()
	if !ok {
		return "", "", "", false
	}

	version := strings.TrimPrefix(moduleVersion, "v")
	if version == "" {
		return "", "", "", false
	}

	commit := "unknown"
	date := "unknown"
	if pseudoDate, pseudoCommit := parsePseudoVersion(moduleVersion); pseudoCommit != "" {
		commit = pseudoCommit
		if pseudoDate != "" {
			date = pseudoDate
		}
	}

	return version, commit, date, true
}

func containerlabModuleVersion() (string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return "", false
	}

	for _, dep := range info.Deps {
		if dep.Path != containerlabModulePath {
			continue
		}

		if dep.Replace != nil {
			if dep.Replace.Version != "" {
				return dep.Replace.Version, true
			}
			if dep.Replace.Path != "" {
				return "devel", true
			}
		}

		if dep.Version != "" {
			return dep.Version, true
		}

		return "", false
	}

	return "", false
}

func releaseNotesURL(version string) string {
	slug := docsLinkFromVersion(version)
	if slug == "" {
		return ""
	}

	return containerlabReleaseNotesBaseURL + slug
}

func docsLinkFromVersion(version string) string {
	major, minor, patch, ok := parseVersionSegments(version)
	if !ok {
		return ""
	}

	rel := fmt.Sprintf("%d.%d/", major, minor)
	if patch != 0 {
		rel += fmt.Sprintf("#%d%d%d", major, minor, patch)
	}

	return rel
}

func parseVersionSegments(version string) (int, int, int, bool) {
	v := strings.TrimPrefix(version, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, 0, false
	}

	majorStr := leadingDigits(parts[0])
	minorStr := leadingDigits(parts[1])
	if majorStr == "" || minorStr == "" {
		return 0, 0, 0, false
	}

	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return 0, 0, 0, false
	}

	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, 0, false
	}

	patch := 0
	if len(parts) == 3 {
		patchStr := leadingDigits(parts[2])
		if patchStr != "" {
			parsedPatch, err := strconv.Atoi(patchStr)
			if err == nil {
				patch = parsedPatch
			}
		}
	}

	return major, minor, patch, true
}

func leadingDigits(value string) string {
	idx := 0
	for idx < len(value) && value[idx] >= '0' && value[idx] <= '9' {
		idx++
	}
	return value[:idx]
}

func parsePseudoVersion(version string) (string, string) {
	v := strings.TrimPrefix(version, "v")
	parts := strings.Split(v, "-")
	if len(parts) < 3 {
		return "", ""
	}

	commit := parts[len(parts)-1]
	timestamp := parts[len(parts)-2]
	if len(timestamp) != 14 {
		return "", commit
	}

	parsed, err := time.Parse("20060102150405", timestamp)
	if err != nil {
		return "", commit
	}

	return parsed.UTC().Format(time.RFC3339), commit
}

func buildContainerlabVersionCheckResult(ctx context.Context) (string, error) {
	if versionCheckDisabled() {
		return "Version check disabled via CLAB_VERSION_CHECK", nil
	}

	currentVersion, _, _, ok := containerlabVersionDetails()
	if !ok {
		return "", fmt.Errorf("containerlab module version not found in build info")
	}

	latestVersion, err := fetchLatestContainerlabVersion(ctx)
	if err != nil {
		return "", err
	}

	if cmp, ok := compareContainerlabVersions(currentVersion, latestVersion); ok {
		switch {
		case cmp < 0:
			return formatNewVersionMessage(latestVersion), nil
		case cmp == 0:
			return fmt.Sprintf("You are on the latest version (%s)", currentVersion), nil
		default:
			return fmt.Sprintf("You are on a newer version (%s) than the latest release (%s)", currentVersion, latestVersion), nil
		}
	}

	return fmt.Sprintf("Latest containerlab version: %s (current: %s)", latestVersion, currentVersion), nil
}

func versionCheckDisabled() bool {
	value := strings.ToLower(os.Getenv("CLAB_VERSION_CHECK"))
	return strings.Contains(value, "disable")
}

func fetchLatestContainerlabVersion(ctx context.Context) (string, error) {
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, containerlabLatestReleaseURL, http.NoBody)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", fmt.Errorf("no response while fetching latest containerlab release")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location == "" {
		return "", fmt.Errorf("latest release redirect location missing")
	}

	parts := strings.Split(location, "releases/tag/")
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected latest release location %q", location)
	}

	tag := strings.TrimSpace(parts[1])
	tag = strings.SplitN(tag, "?", 2)[0]
	tag = strings.SplitN(tag, "#", 2)[0]
	tag = strings.TrimPrefix(tag, "v")
	if tag == "" {
		return "", fmt.Errorf("latest release tag missing")
	}

	return tag, nil
}

func compareContainerlabVersions(currentVersion, latestVersion string) (int, bool) {
	currentSemver, ok := normalizeVersionToSemver(currentVersion)
	if !ok {
		return 0, false
	}

	latestSemver, ok := normalizeVersionToSemver(latestVersion)
	if !ok {
		return 0, false
	}

	return semver.Compare(currentSemver, latestSemver), true
}

func normalizeVersionToSemver(version string) (string, bool) {
	major, minor, patch, ok := parseVersionSegments(version)
	if !ok {
		return "", false
	}

	return fmt.Sprintf("v%d.%d.%d", major, minor, patch), true
}

func formatNewVersionMessage(latestVersion string) string {
	releaseNotes := releaseNotesURL(latestVersion)
	if releaseNotes == "" {
		return fmt.Sprintf("A newer containerlab version (%s) is available!", latestVersion)
	}

	return fmt.Sprintf(
		"A newer containerlab version (%s) is available!\nRelease notes: %s\nRun 'sudo clab version upgrade' or see %s for installation options.",
		latestVersion,
		releaseNotes,
		containerlabInstallURL,
	)
}
