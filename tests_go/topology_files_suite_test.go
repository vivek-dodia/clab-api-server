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

type applyLabResponse struct {
	DryRun            bool              `json:"dryRun"`
	DeployedLab       bool              `json:"deployedLab"`
	LabName           string            `json:"labName"`
	AddedNodes        []string          `json:"addedNodes"`
	DeletedNodes      []string          `json:"deletedNodes"`
	RecreatedNodes    []string          `json:"recreatedNodes"`
	StartedNodes      []string          `json:"startedNodes"`
	AddedLinks        []string          `json:"addedLinks"`
	DeletedEndpoints  []string          `json:"deletedEndpoints"`
	RestartedNodes    []string          `json:"restartedNodes"`
	NodeChangeReasons map[string]string `json:"nodeChangeReasons"`
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

func (s *TopologyFilesSuite) TestApplyTopologyFileAddsNode() {
	labName := fmt.Sprintf("%s-apply-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	topologyPath := labName + ".clab.yml"
	initialTopology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", labName)
	updatedTopology := s.topologyWithExtraLinuxNode(initialTopology, "srl3")

	defer s.deleteTopologyFile(labName, topologyPath)
	defer s.cleanupLab(labName, true)

	s.logTest("Writing and deploying base topology file for apply test lab '%s'", labName)
	bodyBytes, statusCode, err := s.doRequest("PUT", s.topologyFileURL(labName, topologyPath), s.apiUserHeaders, bytes.NewBufferString(initialTopology), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 writing topology file. Body: %s", string(bodyBytes))

	deployURL := fmt.Sprintf("%s/api/v1/labs/%s/deploy?path=%s", s.cfg.APIURL, labName, url.QueryEscape(topologyPath))
	bodyBytes, statusCode, err = s.doRequest("POST", deployURL, s.apiUserHeaders, nil, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 deploying topology file. Body: %s", string(bodyBytes))

	s.assertInspectNodeNames(labName, s.apiUserHeaders, []string{"srl1", "srl2"}, []string{"srl3"})

	s.logTest("Updating topology file for lab '%s' with an additional node", labName)
	bodyBytes, statusCode, err = s.doRequest("PUT", s.topologyFileURL(labName, topologyPath), s.apiUserHeaders, bytes.NewBufferString(updatedTopology), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 updating topology file. Body: %s", string(bodyBytes))

	applyURL := fmt.Sprintf("%s/api/v1/labs/%s/apply", s.cfg.APIURL, labName)
	dryRunURL := applyURL + "?dryRun=true"

	s.logTest("Dry-running apply for lab '%s'", labName)
	bodyBytes, statusCode, err = s.doRequest("POST", dryRunURL, s.apiUserHeaders, nil, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 dry-running apply. Body: %s", string(bodyBytes))

	var dryRunResp applyLabResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &dryRunResp), "Failed to unmarshal dry-run apply response. Body: %s", string(bodyBytes))
	s.Require().True(dryRunResp.DryRun, "Expected dryRun=true. Body: %s", string(bodyBytes))
	s.Require().False(dryRunResp.DeployedLab, "Expected dry-run against existing lab not to deploy a missing lab. Body: %s", string(bodyBytes))
	s.Require().Equal(labName, dryRunResp.LabName, "Expected apply response lab name. Body: %s", string(bodyBytes))
	s.Require().Contains(dryRunResp.AddedNodes, "srl3", "Expected dry-run apply to report srl3 as an added node. Body: %s", string(bodyBytes))
	s.assertInspectNodeNames(labName, s.apiUserHeaders, []string{"srl1", "srl2"}, []string{"srl3"})

	s.logTest("Applying topology changes for lab '%s'", labName)
	bodyBytes, statusCode, err = s.doRequest("POST", applyURL, s.apiUserHeaders, nil, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 applying topology changes. Body: %s", string(bodyBytes))

	var applyResp applyLabResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &applyResp), "Failed to unmarshal apply response. Body: %s", string(bodyBytes))
	s.Require().False(applyResp.DryRun, "Expected dryRun=false. Body: %s", string(bodyBytes))
	s.Require().Equal(labName, applyResp.LabName, "Expected apply response lab name. Body: %s", string(bodyBytes))
	s.Require().Contains(applyResp.AddedNodes, "srl3", "Expected apply to report srl3 as an added node. Body: %s", string(bodyBytes))

	s.assertInspectNodeNames(labName, s.apiUserHeaders, []string{"srl1", "srl2", "srl3"}, nil)
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

func (s *TopologyFilesSuite) topologyWithExtraLinuxNode(topologyContent, nodeName string) string {
	s.T().Helper()

	var topology map[string]interface{}
	s.Require().NoError(json.Unmarshal([]byte(topologyContent), &topology), "Failed to parse topology content")

	topologySection, ok := topology["topology"].(map[string]interface{})
	s.Require().True(ok, "Expected topology section in test topology")

	nodes, ok := topologySection["nodes"].(map[string]interface{})
	s.Require().True(ok, "Expected nodes section in test topology")
	nodes[nodeName] = map[string]interface{}{
		"kind": "linux",
	}

	updated, err := json.MarshalIndent(topology, "", "  ")
	s.Require().NoError(err, "Failed to marshal updated topology")

	return string(updated)
}

func (s *TopologyFilesSuite) assertInspectNodeNames(labName string, headers http.Header, expected, absent []string) {
	s.T().Helper()

	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("GET", inspectURL, headers, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to inspect lab '%s'", labName)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 inspecting lab '%s'. Body: %s", labName, string(bodyBytes))

	var containers []ClabContainerInfo
	s.Require().NoError(json.Unmarshal(bodyBytes, &containers), "Failed to unmarshal inspect response. Body: %s", string(bodyBytes))

	nodeNames := make(map[string]bool, len(containers))
	for _, container := range containers {
		nodeNames[container.NodeName] = true
	}

	for _, nodeName := range expected {
		s.Require().True(nodeNames[nodeName], "Expected lab '%s' to include node %q. Body: %s", labName, nodeName, string(bodyBytes))
	}
	for _, nodeName := range absent {
		s.Require().False(nodeNames[nodeName], "Expected lab '%s' not to include node %q. Body: %s", labName, nodeName, string(bodyBytes))
	}
}
