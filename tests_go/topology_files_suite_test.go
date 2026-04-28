package tests_go

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type TopologyFilesSuite struct {
	BaseSuite

	apiUserHeaders   http.Header
	superuserHeaders http.Header
}

func TestTopologyFilesSuite(t *testing.T) {
	suite.Run(t, new(TopologyFilesSuite))
}

func (s *TopologyFilesSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserHeaders, s.superuserHeaders = s.loginBothUsers()
}

type topologyEntry struct {
	LabName             string `json:"labName"`
	YamlFileName        string `json:"yamlFileName"`
	AnnotationsFileName string `json:"annotationsFileName"`
	HasAnnotations      bool   `json:"hasAnnotations"`
	DeploymentState     string `json:"deploymentState"`
}

func (s *TopologyFilesSuite) topologyFileURL(labName, relPath string) string {
	reqURL, _ := url.Parse(fmt.Sprintf("%s/api/v1/labs/%s/topology/file", s.cfg.APIURL, labName))
	query := reqURL.Query()
	query.Set("path", relPath)
	reqURL.RawQuery = query.Encode()
	return reqURL.String()
}

func (s *TopologyFilesSuite) deleteTopologyFile(labName, relPath string) {
	s.T().Helper()
	_, _, _ = s.doRequest("DELETE", s.topologyFileURL(labName, relPath), s.apiUserHeaders, nil, s.cfg.RequestTimeout)
}

func (s *TopologyFilesSuite) TestTopologyFileLifecycleAndDeploy() {
	labName := fmt.Sprintf("%s-topofile-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	topologyPath := labName + ".clab.yml"
	extraPath := "notes.txt"
	renamedPath := "notes-renamed.txt"
	topologyContent := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", labName)

	defer s.deleteTopologyFile(labName, topologyPath)
	defer s.deleteTopologyFile(labName, renamedPath)
	defer s.deleteTopologyFile(labName, extraPath)
	defer s.cleanupLab(labName, true)

	s.logTest("Writing topology file for undeployed lab '%s'", labName)
	bodyBytes, statusCode, err := s.doRequest("PUT", s.topologyFileURL(labName, topologyPath), s.apiUserHeaders, bytes.NewBufferString(topologyContent), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 writing topology file. Body: %s", string(bodyBytes))

	listURL := fmt.Sprintf("%s/api/v1/labs/topology/files", s.cfg.APIURL)
	bodyBytes, statusCode, err = s.doRequest("GET", listURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 listing topology files. Body: %s", string(bodyBytes))

	var entries []topologyEntry
	s.Require().NoError(json.Unmarshal(bodyBytes, &entries), "Failed to unmarshal topology file list. Body: %s", string(bodyBytes))
	found := false
	for _, entry := range entries {
		if entry.LabName == labName && entry.YamlFileName == topologyPath {
			found = true
			s.Require().Equal("undeployed", entry.DeploymentState)
			break
		}
	}
	s.Require().True(found, "Expected topology file entry for lab %q. Body: %s", labName, string(bodyBytes))

	_, statusCode, err = s.doRequest("HEAD", s.topologyFileURL(labName, topologyPath), s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 from HEAD for topology file")

	bodyBytes, statusCode, err = s.doRequest("GET", s.topologyFileURL(labName, topologyPath), s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 reading topology file. Body: %s", string(bodyBytes))
	s.Require().Contains(string(bodyBytes), labName)

	s.logTest("Deploying topology file for lab '%s'", labName)
	deployURL := fmt.Sprintf("%s/api/v1/labs/%s/deploy?path=%s", s.cfg.APIURL, labName, url.QueryEscape(topologyPath))
	bodyBytes, statusCode, err = s.doRequest("POST", deployURL, s.apiUserHeaders, nil, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 deploying topology file. Body: %s", string(bodyBytes))

	var deployResp ClabInspectOutput
	s.Require().NoError(json.Unmarshal(bodyBytes, &deployResp), "Failed to unmarshal deploy response. Body: %s", string(bodyBytes))
	s.Require().Contains(deployResp, labName)

	s.logTest("Renaming and deleting an auxiliary file for lab '%s'", labName)
	bodyBytes, statusCode, err = s.doRequest("PUT", s.topologyFileURL(labName, extraPath), s.apiUserHeaders, bytes.NewBufferString("integration test note\n"), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 writing auxiliary topology file. Body: %s", string(bodyBytes))

	renameURL := fmt.Sprintf("%s/api/v1/labs/%s/topology/file/rename", s.cfg.APIURL, labName)
	renamePayload := map[string]string{"oldPath": extraPath, "newPath": renamedPath}
	bodyBytes, statusCode, err = s.doRequest("POST", renameURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(renamePayload)), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 renaming topology file. Body: %s", string(bodyBytes))

	bodyBytes, statusCode, err = s.doRequest("DELETE", s.topologyFileURL(labName, renamedPath), s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 deleting renamed topology file. Body: %s", string(bodyBytes))
}

func (s *TopologyFilesSuite) TestTopologyFileRejectsInvalidPaths() {
	labName := fmt.Sprintf("%s-topofile-invalid-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	invalidURL := s.topologyFileURL(labName, "../escape.clab.yml")

	bodyBytes, statusCode, err := s.doRequest("GET", invalidURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for path traversal. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "invalid file path")

	bodyBytes, statusCode, err = s.doRequest("PUT", invalidURL, s.apiUserHeaders, bytes.NewBufferString("name: bad"), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 writing path traversal. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "invalid file path")
}

func (s *TopologyFilesSuite) TestTopologyYamlAnnotationsAndEventsEndpoints() {
	labName := fmt.Sprintf("%s-topodoc-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	yamlPath := labName + ".clab.yml"
	annotationsPath := yamlPath + ".annotations.json"
	topologyContent := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", labName)
	annotations := `{"nodes":{"srl1":{"x":10,"y":20}}}`

	defer s.deleteTopologyFile(labName, annotationsPath)
	defer s.deleteTopologyFile(labName, yamlPath)

	yamlURL := fmt.Sprintf("%s/api/v1/labs/%s/topology/yaml", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("PUT", yamlURL, s.apiUserHeaders, bytes.NewBufferString(topologyContent), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 writing topology YAML document. Body: %s", string(bodyBytes))

	bodyBytes, statusCode, err = s.doRequest("GET", yamlURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 reading topology YAML document. Body: %s", string(bodyBytes))
	s.Require().Contains(string(bodyBytes), labName)

	annotationsURL := fmt.Sprintf("%s/api/v1/labs/%s/topology/annotations", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err = s.doRequest("PUT", annotationsURL, s.apiUserHeaders, bytes.NewBufferString(annotations), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 writing topology annotations. Body: %s", string(bodyBytes))

	bodyBytes, statusCode, err = s.doRequest("GET", annotationsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 reading topology annotations. Body: %s", string(bodyBytes))
	s.Require().JSONEq(annotations, string(bodyBytes))

	s.assertTopologyEventStreamStarts(labName, yamlPath)
}

func (s *TopologyFilesSuite) assertTopologyEventStreamStarts(labName, relPath string) {
	s.T().Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	reqURL, _ := url.Parse(fmt.Sprintf("%s/api/v1/labs/%s/topology/events", s.cfg.APIURL, labName))
	query := reqURL.Query()
	query.Set("path", relPath)
	reqURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	s.Require().NoError(err)
	req.Header = s.apiUserHeaders

	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode, "Expected 200 opening topology event stream")
	s.Require().Contains(resp.Header.Get("Content-Type"), "application/x-ndjson")
}

func (s *TopologyFilesSuite) TestTopologyFileNonOwnerCannotReadRuntimeOwnerFile() {
	labName, apiHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	topologyPath := labName + ".clab.yml"
	readURL := s.topologyFileURL(labName, topologyPath)

	bodyBytes, statusCode, err := s.doRequest("GET", readURL, apiHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Owner should be able to read topology file. Body: %s", string(bodyBytes))

	bodyBytes, statusCode, err = s.doRequest("GET", readURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusNotFound, statusCode, "Topology file endpoint should not expose another user's lab file. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "File not found")
}
