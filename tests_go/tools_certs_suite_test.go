// tests_go/tools_certs_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
)

// ToolsCertsSuite tests certificate tool endpoints (CA create, cert sign).
type ToolsCertsSuite struct {
	BaseSuite
	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header
}

func TestToolsCertsSuite(t *testing.T) {
	suite.Run(t, new(ToolsCertsSuite))
}

func (s *ToolsCertsSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.apiUserToken)
	s.Require().NotEmpty(s.superuserToken)
}

func (s *ToolsCertsSuite) TestCreateCAForbiddenForAPIUser() {
	s.logTest("Creating CA as API user (expecting 403)")

	url := fmt.Sprintf("%s/api/v1/tools/certs/ca", s.cfg.APIURL)
	payload := map[string]interface{}{"name": "gotest-ca-" + s.randomSuffix(5)}
	body := bytes.NewBuffer(s.mustMarshal(payload))

	respBody, statusCode, err := s.doRequest("POST", url, s.apiUserHeaders, body, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected 403 for non-superuser CA create. Body: %s", string(respBody))
}

func (s *ToolsCertsSuite) TestSignCertForbiddenForAPIUser() {
	s.logTest("Signing cert as API user (expecting 403)")

	url := fmt.Sprintf("%s/api/v1/tools/certs/sign", s.cfg.APIURL)
	payload := map[string]interface{}{
		"name":   "gotest-node-" + s.randomSuffix(5),
		"hosts":  []string{"127.0.0.1"},
		"caName": "does-not-matter",
	}
	body := bytes.NewBuffer(s.mustMarshal(payload))

	respBody, statusCode, err := s.doRequest("POST", url, s.apiUserHeaders, body, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected 403 for non-superuser cert sign. Body: %s", string(respBody))
}

func (s *ToolsCertsSuite) TestSignCertNotFoundWhenCAIsMissing() {
	s.logTest("Signing cert with missing CA (expecting 404)")

	url := fmt.Sprintf("%s/api/v1/tools/certs/sign", s.cfg.APIURL)
	payload := map[string]interface{}{
		"name":   "gotest-node-" + s.randomSuffix(5),
		"hosts":  []string{"127.0.0.1"},
		"caName": "gotest-missing-ca-" + s.randomSuffix(5),
	}
	body := bytes.NewBuffer(s.mustMarshal(payload))

	respBody, statusCode, err := s.doRequest("POST", url, s.superuserHeaders, body, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusNotFound, statusCode, "Expected 404 when CA does not exist. Body: %s", string(respBody))
}

func (s *ToolsCertsSuite) TestCreateCAAndSignCertAsSuperuser() {
	caName := "gotest-ca-" + s.randomSuffix(6)
	certName := "gotest-node-" + s.randomSuffix(6)

	s.logTest("Creating CA '%s' and signing cert '%s' as superuser", caName, certName)

	createURL := fmt.Sprintf("%s/api/v1/tools/certs/ca", s.cfg.APIURL)
	createPayload := map[string]interface{}{
		"name": caName,
	}

	createBody := bytes.NewBuffer(s.mustMarshal(createPayload))
	createRespBody, createStatus, createErr := s.doRequest("POST", createURL, s.superuserHeaders, createBody, s.cfg.RequestTimeout)
	s.Require().NoError(createErr)
	s.Require().Equal(http.StatusOK, createStatus, "Expected 200 for CA create. Body: %s", string(createRespBody))

	var caResp struct {
		Message  string `json:"message"`
		CertPath string `json:"certPath"`
		KeyPath  string `json:"keyPath"`
		CSRPath  string `json:"csrPath"`
	}
	s.Require().NoError(json.Unmarshal(createRespBody, &caResp), "Failed to unmarshal CA response. Body: %s", string(createRespBody))
	s.Assert().NotEmpty(caResp.Message)
	s.Assert().Contains(caResp.CertPath, caName)
	s.Assert().Contains(caResp.KeyPath, caName)

	signURL := fmt.Sprintf("%s/api/v1/tools/certs/sign", s.cfg.APIURL)
	signPayload := map[string]interface{}{
		"name":   certName,
		"hosts":  []string{"127.0.0.1", "localhost"},
		"caName": caName,
	}
	signBody := bytes.NewBuffer(s.mustMarshal(signPayload))
	signRespBody, signStatus, signErr := s.doRequest("POST", signURL, s.superuserHeaders, signBody, s.cfg.RequestTimeout)
	s.Require().NoError(signErr)
	s.Require().Equal(http.StatusOK, signStatus, "Expected 200 for cert sign. Body: %s", string(signRespBody))

	var signResp struct {
		Message  string `json:"message"`
		CertPath string `json:"certPath"`
		KeyPath  string `json:"keyPath"`
		CSRPath  string `json:"csrPath"`
	}
	s.Require().NoError(json.Unmarshal(signRespBody, &signResp), "Failed to unmarshal sign response. Body: %s", string(signRespBody))
	s.Assert().NotEmpty(signResp.Message)
	s.Assert().Contains(signResp.CertPath, caName)
	s.Assert().Contains(signResp.CertPath, certName)
	s.Assert().Contains(signResp.KeyPath, caName)
	s.Assert().Contains(signResp.KeyPath, certName)

	// Best-effort cleanup of generated cert files on disk (under the current user's home).
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		caDir := filepath.Join(homeDir, ".clab", "certs", caName)
		_ = os.RemoveAll(caDir)
	}

	if !s.T().Failed() {
		s.logSuccess("Created CA '%s' and signed cert '%s' successfully", caName, certName)
	}
}
