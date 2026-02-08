// tests_go/lab_archive_suite_test.go
package tests_go

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

// LabArchiveSuite tests deploying labs from an uploaded archive.
type LabArchiveSuite struct {
	BaseSuite
	apiUserToken   string
	apiUserHeaders http.Header
}

func TestLabArchiveSuite(t *testing.T) {
	suite.Run(t, new(LabArchiveSuite))
}

func (s *LabArchiveSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.Require().NotEmpty(s.apiUserToken)
}

func (s *LabArchiveSuite) TestDeployLabArchiveMissingLabNameQueryParam() {
	s.logTest("Deploying lab archive without labName query param (expecting 400)")

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	s.Require().NoError(writer.Close())

	headers := s.getAuthHeaders(s.apiUserToken)
	headers.Set("Content-Type", writer.FormDataContentType())

	url := fmt.Sprintf("%s/api/v1/labs/archive", s.cfg.APIURL)
	respBody, statusCode, err := s.doRequest("POST", url, headers, &body, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusBadRequest, statusCode, "Expected 400 for missing labName. Body: %s", string(respBody))
}

func (s *LabArchiveSuite) TestDeployLabArchiveZipSuccess() {
	labName := fmt.Sprintf("%s-arch-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	defer s.cleanupLab(labName, true)

	s.logTest("Deploying lab '%s' via /api/v1/labs/archive (zip upload)", labName)

	// Build YAML topology from the same JSON content used by other tests.
	topologyJSON := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", labName)
	var topoData map[string]interface{}
	s.Require().NoError(json.Unmarshal([]byte(topologyJSON), &topoData), "Failed to parse test topology JSON")

	yamlBytes, err := yaml.Marshal(topoData)
	s.Require().NoError(err, "Failed to marshal topology to YAML")

	// Create a zip archive in memory containing "<labName>.clab.yml" at the archive root.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	fw, err := zw.Create(labName + ".clab.yml")
	s.Require().NoError(err, "Failed to create zip entry")
	_, err = fw.Write(yamlBytes)
	s.Require().NoError(err, "Failed to write zip entry data")
	s.Require().NoError(zw.Close(), "Failed to close zip writer")

	// Create multipart/form-data request body.
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("labArchive", labName+".zip")
	s.Require().NoError(err, "Failed to create multipart file part")
	_, err = part.Write(zipBuf.Bytes())
	s.Require().NoError(err, "Failed to write multipart file bytes")

	s.Require().NoError(writer.Close(), "Failed to close multipart writer")

	headers := s.getAuthHeaders(s.apiUserToken)
	headers.Set("Content-Type", writer.FormDataContentType())

	url := fmt.Sprintf("%s/api/v1/labs/archive?labName=%s", s.cfg.APIURL, labName)
	respBody, statusCode, err := s.doRequest("POST", url, headers, &body, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 deploying lab from archive. Body: %s", string(respBody))

	var out ClabInspectOutput
	s.Require().NoError(json.Unmarshal(respBody, &out), "Failed to unmarshal archive deploy response. Body: %s", string(respBody))
	s.Assert().Contains(out, labName, "Expected deployed lab '%s' to be present in response", labName)
	if nodes, ok := out[labName]; ok {
		s.Assert().NotEmpty(nodes, "Expected deployed lab to have container entries in response")
	}

	if !s.T().Failed() {
		s.logSuccess("Archive deploy succeeded for lab '%s'", labName)
	}
}
