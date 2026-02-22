package tests_go

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type LabCleanupSuite struct {
	BaseSuite
	superuserToken   string
	superuserHeaders http.Header
}

func TestLabCleanupSuite(t *testing.T) {
	suite.Run(t, new(LabCleanupSuite))
}

func (s *LabCleanupSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.superuserToken)
}

func (s *LabCleanupSuite) TestDestroyCleanupRemovesGeneratedDirForExternalTopology() {
	labName := fmt.Sprintf("%s-cleanup-%s", s.cfg.LabNamePrefix, s.randomSuffix(6))
	tempDir, err := os.MkdirTemp("", "clab-api-cleanup-*")
	s.Require().NoError(err, "Failed to create temporary test directory")
	defer os.RemoveAll(tempDir)

	topoPath := filepath.Join(tempDir, "lab.clab.yml")
	topology := fmt.Sprintf(`name: %s
topology:
  kinds:
    linux:
      image: ghcr.io/srl-labs/network-multitool
  nodes:
    n1:
      kind: linux
`, labName)
	err = os.WriteFile(topoPath, []byte(topology), 0644)
	s.Require().NoError(err, "Failed to write topology file")

	deployOutput, err := s.runContainerlabWithFallback(s.cfg.DeployTimeout, "deploy", "-t", topoPath, "--reconfigure")
	if err != nil {
		s.T().Skipf("Skipping test: unable to deploy lab with containerlab CLI: %v\nOutput:\n%s", err, deployOutput)
	}

	defer func() {
		_, _ = s.runContainerlabWithFallback(s.cfg.CleanupTimeout, "destroy", "-t", topoPath, "--cleanup", "--yes")
	}()

	generatedDir := filepath.Join(tempDir, "clab-"+labName)
	if _, statErr := os.Stat(generatedDir); statErr != nil {
		s.Require().NoError(statErr, "Expected generated lab directory to exist after deploy: %s", generatedDir)
	}

	bodyBytes, statusCode, destroyErr := s.destroyLab(s.superuserHeaders, labName, true, s.cfg.CleanupTimeout)
	s.Require().NoError(destroyErr, "Failed to execute destroy request")
	s.Require().Equal(http.StatusOK, statusCode, "Destroy request returned non-OK status. Body: %s", string(bodyBytes))

	// Give filesystem operations a short moment to settle before assertion.
	time.Sleep(2 * time.Second)

	_, statErr := os.Stat(generatedDir)
	s.Require().Truef(os.IsNotExist(statErr),
		"Expected generated lab directory to be removed by cleanup=true: %s (stat err: %v)",
		generatedDir,
		statErr,
	)
}

func (s *LabCleanupSuite) TestDestroyCleanupDoesNotPurgeLabDirByDefault() {
	labName := fmt.Sprintf("%s-purge-default-%s", s.cfg.LabNamePrefix, s.randomSuffix(6))
	homeDir, err := os.UserHomeDir()
	s.Require().NoError(err, "Failed to get user home directory")

	labDir := filepath.Join(homeDir, ".clab", labName)
	topoPath := filepath.Join(labDir, "lab.clab.yml")
	s.Require().NoError(os.MkdirAll(labDir, 0750), "Failed to create lab directory")
	defer os.RemoveAll(labDir)

	topology := fmt.Sprintf(`name: %s
topology:
  kinds:
    linux:
      image: ghcr.io/srl-labs/network-multitool
  nodes:
    n1:
      kind: linux
`, labName)
	err = os.WriteFile(topoPath, []byte(topology), 0644)
	s.Require().NoError(err, "Failed to write topology file")

	deployOutput, err := s.runContainerlabWithFallback(s.cfg.DeployTimeout, "deploy", "-t", topoPath, "--reconfigure")
	if err != nil {
		s.T().Skipf("Skipping test: unable to deploy lab with containerlab CLI: %v\nOutput:\n%s", err, deployOutput)
	}

	defer func() {
		_, _ = s.runContainerlabWithFallback(s.cfg.CleanupTimeout, "destroy", "-t", topoPath, "--cleanup", "--yes")
	}()

	generatedDir := filepath.Join(labDir, "clab-"+labName)
	_, statErr := os.Stat(generatedDir)
	s.Require().NoError(statErr, "Expected generated runtime directory to exist after deploy")

	bodyBytes, statusCode, destroyErr := s.destroyLabWithQuery(s.superuserHeaders, labName, map[string]string{
		"cleanup": "true",
	}, s.cfg.CleanupTimeout)
	s.Require().NoError(destroyErr, "Failed to execute destroy request")
	s.Require().Equal(http.StatusOK, statusCode, "Destroy request returned non-OK status. Body: %s", string(bodyBytes))

	time.Sleep(2 * time.Second)

	_, statErr = os.Stat(labDir)
	s.Require().NoError(statErr, "Expected lab directory to remain when purgeLabDir is not requested")
	_, statErr = os.Stat(topoPath)
	s.Require().NoError(statErr, "Expected topology file to remain when purgeLabDir is not requested")
	_, statErr = os.Stat(generatedDir)
	s.Require().True(os.IsNotExist(statErr), "Expected generated runtime directory to be removed when cleanup=true")
}

func (s *LabCleanupSuite) TestDestroyCleanupWithPurgeLabDirRemovesLabDir() {
	labName := fmt.Sprintf("%s-purge-true-%s", s.cfg.LabNamePrefix, s.randomSuffix(6))
	homeDir, err := os.UserHomeDir()
	s.Require().NoError(err, "Failed to get user home directory")

	labDir := filepath.Join(homeDir, ".clab", labName)
	topoPath := filepath.Join(labDir, "lab.clab.yml")
	s.Require().NoError(os.MkdirAll(labDir, 0750), "Failed to create lab directory")
	defer os.RemoveAll(labDir)

	topology := fmt.Sprintf(`name: %s
topology:
  kinds:
    linux:
      image: ghcr.io/srl-labs/network-multitool
  nodes:
    n1:
      kind: linux
`, labName)
	err = os.WriteFile(topoPath, []byte(topology), 0644)
	s.Require().NoError(err, "Failed to write topology file")

	deployOutput, err := s.runContainerlabWithFallback(s.cfg.DeployTimeout, "deploy", "-t", topoPath, "--reconfigure")
	if err != nil {
		s.T().Skipf("Skipping test: unable to deploy lab with containerlab CLI: %v\nOutput:\n%s", err, deployOutput)
	}

	defer func() {
		_, _ = s.runContainerlabWithFallback(s.cfg.CleanupTimeout, "destroy", "-t", topoPath, "--cleanup", "--yes")
	}()

	bodyBytes, statusCode, destroyErr := s.destroyLabWithQuery(s.superuserHeaders, labName, map[string]string{
		"cleanup":     "true",
		"purgeLabDir": "true",
	}, s.cfg.CleanupTimeout)
	s.Require().NoError(destroyErr, "Failed to execute destroy request")
	s.Require().Equal(http.StatusOK, statusCode, "Destroy request returned non-OK status. Body: %s", string(bodyBytes))

	time.Sleep(2 * time.Second)

	_, statErr := os.Stat(labDir)
	s.Require().Truef(os.IsNotExist(statErr),
		"Expected lab directory to be removed when purgeLabDir=true: %s (stat err: %v)",
		labDir,
		statErr,
	)
}

func (s *LabCleanupSuite) TestDestroyCleanupWithPurgeLabDirAllowsSuperuserForOtherOwnerLab() {
	labName := fmt.Sprintf("%s-purge-su-%s", s.cfg.LabNamePrefix, s.randomSuffix(6))

	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	apiUserHeaders := s.getAuthHeaders(apiUserToken)

	topology := fmt.Sprintf(`{
  "name": "%s",
  "topology": {
    "kinds": {
      "linux": {
        "image": "ghcr.io/srl-labs/network-multitool:latest"
      }
    },
    "nodes": {
      "n1": {
        "kind": "linux"
      }
    }
  }
}`, labName)
	bodyBytes, statusCode, createErr := s.createLab(apiUserHeaders, labName, topology, false, s.cfg.DeployTimeout)
	s.Require().NoError(createErr, "Failed to execute create request")
	s.Require().Equal(http.StatusOK, statusCode, "Create request returned non-OK status. Body: %s", string(bodyBytes))

	defer func() {
		_, _, _ = s.destroyLab(s.superuserHeaders, labName, true, s.cfg.CleanupTimeout)
	}()

	apiUser, lookupErr := user.Lookup(s.cfg.APIUserUser)
	if lookupErr != nil {
		s.T().Skipf("Skipping test: unable to lookup API user '%s': %v", s.cfg.APIUserUser, lookupErr)
	}

	labDir := filepath.Join(apiUser.HomeDir, ".clab", labName)
	exists, existsErr := s.pathExistsAsUser(labDir, s.cfg.APIUserUser, s.cfg.RequestTimeout)
	s.Require().NoError(existsErr, "Failed to verify API-user lab directory existence before destroy")
	s.Require().Truef(exists, "Expected API-user lab directory to exist before destroy: %s", labDir)

	bodyBytes, statusCode, destroyErr := s.destroyLabWithQuery(s.superuserHeaders, labName, map[string]string{
		"cleanup":     "true",
		"purgeLabDir": "true",
	}, s.cfg.CleanupTimeout)
	s.Require().NoError(destroyErr, "Failed to execute destroy request")
	s.Require().Equal(http.StatusOK, statusCode, "Destroy request returned non-OK status. Body: %s", string(bodyBytes))

	time.Sleep(2 * time.Second)

	exists, existsErr = s.pathExistsAsUser(labDir, s.cfg.APIUserUser, s.cfg.RequestTimeout)
	s.Require().NoError(existsErr, "Failed to verify API-user lab directory existence after destroy")
	s.Require().Falsef(exists,
		"Expected superuser purge to remove API-user lab directory when purgeLabDir=true: %s",
		labDir,
	)
}

func (s *LabCleanupSuite) TestDestroyCleanupWithPurgeLabDirDeniedForNonSuperuserOnOtherOwnerLab() {
	labName := fmt.Sprintf("%s-purge-deny-%s", s.cfg.LabNamePrefix, s.randomSuffix(6))

	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	apiUserHeaders := s.getAuthHeaders(apiUserToken)

	topology := fmt.Sprintf(`{
  "name": "%s",
  "topology": {
    "kinds": {
      "linux": {
        "image": "ghcr.io/srl-labs/network-multitool:latest"
      }
    },
    "nodes": {
      "n1": {
        "kind": "linux"
      }
    }
  }
}`, labName)
	bodyBytes, statusCode, createErr := s.createLab(s.superuserHeaders, labName, topology, false, s.cfg.DeployTimeout)
	s.Require().NoError(createErr, "Failed to execute create request")
	s.Require().Equal(http.StatusOK, statusCode, "Create request returned non-OK status. Body: %s", string(bodyBytes))

	defer func() {
		_, _, _ = s.destroyLab(s.superuserHeaders, labName, true, s.cfg.CleanupTimeout)
	}()

	superuser, lookupErr := user.Lookup(s.cfg.SuperuserUser)
	if lookupErr != nil {
		s.T().Skipf("Skipping test: unable to lookup superuser '%s': %v", s.cfg.SuperuserUser, lookupErr)
	}

	labDir := filepath.Join(superuser.HomeDir, ".clab", labName)
	exists, existsErr := s.pathExistsAsUser(labDir, s.cfg.SuperuserUser, s.cfg.RequestTimeout)
	s.Require().NoError(existsErr, "Failed to verify superuser lab directory existence before non-owner destroy")
	s.Require().Truef(exists, "Expected superuser lab directory to exist before non-owner destroy: %s", labDir)

	bodyBytes, statusCode, destroyErr := s.destroyLabWithQuery(apiUserHeaders, labName, map[string]string{
		"cleanup":     "true",
		"purgeLabDir": "true",
	}, s.cfg.CleanupTimeout)
	s.Require().NoError(destroyErr, "Failed to execute non-owner destroy request")
	s.Require().Truef(
		statusCode == http.StatusForbidden || statusCode == http.StatusNotFound,
		"Expected 403/404 for non-owner destroy+purge, got %d. Body: %s",
		statusCode,
		string(bodyBytes),
	)

	exists, existsErr = s.pathExistsAsUser(labDir, s.cfg.SuperuserUser, s.cfg.RequestTimeout)
	s.Require().NoError(existsErr, "Failed to verify superuser lab directory existence after non-owner destroy")
	s.Require().Truef(exists,
		"Expected non-owner destroy+purge to leave superuser lab directory intact: %s",
		labDir,
	)
}

func (s *LabCleanupSuite) runContainerlabWithFallback(timeout time.Duration, args ...string) (string, error) {
	s.T().Helper()

	if _, err := exec.LookPath("containerlab"); err != nil {
		return "", fmt.Errorf("containerlab binary not found in PATH: %w", err)
	}

	out, err := s.runCommand(timeout, "containerlab", args...)
	if err == nil {
		return out, nil
	}

	combinedLower := strings.ToLower(out + "\n" + err.Error())
	needsRoot := strings.Contains(combinedLower, "requires root privileges") ||
		strings.Contains(combinedLower, "operation not permitted") ||
		strings.Contains(combinedLower, "permission denied")
	if !needsRoot {
		return out, err
	}

	if _, sudoErr := exec.LookPath("sudo"); sudoErr != nil {
		return out, fmt.Errorf("containerlab requires root privileges and sudo is unavailable: %w", sudoErr)
	}

	sudoArgs := append([]string{"-n", "containerlab"}, args...)
	sudoOut, sudoRunErr := s.runCommand(timeout, "sudo", sudoArgs...)
	if sudoRunErr == nil {
		return sudoOut, nil
	}

	return sudoOut, sudoRunErr
}

func (s *LabCleanupSuite) pathExistsAsUser(path, username string, timeout time.Duration) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else if !os.IsPermission(err) {
		return false, err
	}

	if _, err := exec.LookPath("sudo"); err != nil {
		return false, fmt.Errorf("permission denied for path '%s' and sudo is unavailable: %w", path, err)
	}

	_, cmdErr := s.runCommand(timeout, "sudo", "-n", "-u", username, "test", "-e", path)
	if cmdErr == nil {
		return true, nil
	}

	var exitErr *exec.ExitError
	if errors.As(cmdErr, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}

	return false, cmdErr
}

func (s *LabCleanupSuite) destroyLabWithQuery(headers http.Header, labName string, queryParams map[string]string, timeout time.Duration) ([]byte, int, error) {
	s.T().Helper()

	destroyURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	reqURL, _ := url.Parse(destroyURL)

	q := reqURL.Query()
	for key, value := range queryParams {
		q.Set(key, value)
	}
	reqURL.RawQuery = q.Encode()

	return s.doRequest("DELETE", reqURL.String(), headers, nil, timeout)
}

func (s *LabCleanupSuite) runCommand(timeout time.Duration, name string, args ...string) (string, error) {
	s.T().Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("command timed out: %s %s", name, strings.Join(args, " "))
	}

	return string(out), err
}
