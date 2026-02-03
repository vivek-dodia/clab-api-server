// tests_go/version_suite_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

// VersionSuite tests version and health endpoints.
type VersionSuite struct {
	BaseSuite
}

// TestVersionSuite runs the VersionSuite.
func TestVersionSuite(t *testing.T) {
	suite.Run(t, new(VersionSuite))
}

// TestVersionInfoEndpoint tests the version information API endpoint.
func (s *VersionSuite) TestVersionInfoEndpoint() {
	s.logTest("Testing version information endpoint")

	// Get auth token for the API user
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	userHeaders := s.getAuthHeaders(apiUserToken)

	versionURL := fmt.Sprintf("%s/api/v1/version", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", versionURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute version request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for version endpoint. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var versionResp struct {
		VersionInfo string `json:"versionInfo"`
	}

	err = json.Unmarshal(bodyBytes, &versionResp)
	s.Require().NoError(err, "Failed to unmarshal version response. Body: %s", string(bodyBytes))

	// Verify version info field is not empty
	s.Assert().NotEmpty(versionResp.VersionInfo, "VersionInfo field is empty in response")

	versionInfoLower := strings.ToLower(versionResp.VersionInfo)
	s.Assert().Contains(versionInfoLower, "version:", "VersionInfo missing version line")
	s.Assert().Contains(versionInfoLower, "commit:", "VersionInfo missing commit line")
	s.Assert().Contains(versionInfoLower, "date:", "VersionInfo missing date line")
	s.Assert().Contains(versionInfoLower, "github: https://github.com/srl-labs/containerlab",
		"VersionInfo missing containerlab repo link")
	s.Assert().Contains(versionInfoLower, "release notes: https://containerlab.dev/rn/",
		"VersionInfo missing release notes link")

	versionValue, ok := extractInfoValue(versionResp.VersionInfo, "version:")
	s.Require().True(ok, "VersionInfo missing version value")
	s.Require().NotEmpty(versionValue, "VersionInfo version value is empty")
	if versionValue != "devel" {
		s.Assert().True(isSemverLike(versionValue),
			"VersionInfo version value does not look like a semver: %s", versionValue)
	}

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved version information: %s", versionResp.VersionInfo)
	}
}

// TestCheckVersionEndpoint tests the version check API endpoint.
func (s *VersionSuite) TestCheckVersionEndpoint() {
	s.logTest("Testing version check endpoint")

	// Get auth token for the API user
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	userHeaders := s.getAuthHeaders(apiUserToken)

	versionCheckURL := fmt.Sprintf("%s/api/v1/version/check", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", versionCheckURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute version check request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for version check endpoint. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var checkResp struct {
		CheckResult string `json:"checkResult"`
	}

	err = json.Unmarshal(bodyBytes, &checkResp)
	s.Require().NoError(err, "Failed to unmarshal version check response. Body: %s", string(bodyBytes))

	checkResult := strings.TrimSpace(checkResp.CheckResult)
	s.Require().NotEmpty(checkResult, "Version check result is empty")
	s.Require().NotContains(checkResult, "Version check is not available when using containerlab as a library",
		"Version check returned deprecated message")

	allowedPrefixes := []string{
		"You are on the latest version",
		"A newer containerlab version",
		"You are on a newer version",
		"Latest containerlab version:",
		"Version check disabled via CLAB_VERSION_CHECK",
		"Failed fetching latest version information",
	}
	matched := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(checkResult, prefix) {
			matched = true
			break
		}
	}
	s.Require().True(matched, "Unexpected version check result: %s", checkResult)

	if checkResp.CheckResult != "" {
		s.logSuccess("Version check found update info: %s", checkResp.CheckResult)
	} else {
		s.logSuccess("Version check completed - containerlab appears to be up-to-date")
	}
}

var semverLikeRe = regexp.MustCompile(`^\d+\.\d+(\.\d+)?([\-+].+)?$`)

func isSemverLike(version string) bool {
	return semverLikeRe.MatchString(version)
}

func extractInfoValue(info, prefix string) (string, bool) {
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix)), true
		}
	}
	return "", false
}
