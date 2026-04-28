// tests_go/lab_topology_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

// LabTopologySuite tests topology generation endpoints.
type LabTopologySuite struct {
	BaseSuite
	apiUserHeaders http.Header
}

// TestLabTopologySuite runs the LabTopologySuite.
func TestLabTopologySuite(t *testing.T) {
	suite.Run(t, new(LabTopologySuite))
}

// SetupSuite logs in the API user.
func (s *LabTopologySuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(apiUserToken)
	s.Require().NotEmpty(apiUserToken)
}

func (s *LabTopologySuite) TestGenerateTopologyComplexYAML() {
	generatedLabName := fmt.Sprintf("3-tier-clos-%s", s.randomSuffix(5))

	s.logTest("Generating topology for lab '%s'", generatedLabName)

	generateRequest := map[string]interface{}{
		"name":        generatedLabName,
		"defaultKind": "nokia_srlinux",
		"deploy":      false,
		"groupPrefix": "clos-tier",
		"images": map[string]string{
			"nokia_srlinux": "ghcr.io/nokia/srlinux:latest",
		},
		"ipv4Subnet": "172.20.20.0/24",
		"ipv6Subnet": "2001:172:20:20::/64",
		"nodePrefix": "clos-node",
		"tiers": []map[string]interface{}{
			{
				"count": 2,
				"kind":  "nokia_srlinux",
				"type":  "ixrd3",
			},
			{
				"count": 1,
				"kind":  "nokia_srlinux",
				"type":  "ixrd2",
			},
		},
	}

	jsonPayload := s.mustMarshal(generateRequest)

	generateURL := fmt.Sprintf("%s/api/v1/generate", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("POST", generateURL, s.apiUserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute generate topology request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 generating topology for '%s'. Body: %s", generatedLabName, string(bodyBytes))

	var generateResponse struct {
		Message      string `json:"message"`
		TopologyYAML string `json:"topologyYaml"`
	}
	err = json.Unmarshal(bodyBytes, &generateResponse)
	s.Require().NoError(err, "Failed to unmarshal generate topology response. Body: %s", string(bodyBytes))
	s.Require().NotEmpty(generateResponse.TopologyYAML, "Generate response missing topologyYaml")
	s.Assert().Contains(generateResponse.Message, "generated successfully", "Response message should indicate successful generation")

	var topology struct {
		Name     string `yaml:"name"`
		Topology struct {
			Kinds map[string]struct {
				Image string `yaml:"image"`
			} `yaml:"kinds"`
			Nodes map[string]struct {
				Kind  string `yaml:"kind"`
				Type  string `yaml:"type"`
				Group string `yaml:"group"`
			} `yaml:"nodes"`
			Links []struct {
				Endpoints []string `yaml:"endpoints"`
			} `yaml:"links"`
		} `yaml:"topology"`
	}
	err = yaml.Unmarshal([]byte(generateResponse.TopologyYAML), &topology)
	s.Require().NoError(err, "Failed to parse generated topology YAML")

	s.Assert().Equal(generatedLabName, topology.Name, "Generated YAML doesn't contain the lab name")
	s.Require().Contains(topology.Topology.Kinds, "nokia_srlinux", "Generated YAML doesn't contain the node kind")
	s.Assert().Equal("ghcr.io/nokia/srlinux:latest", topology.Topology.Kinds["nokia_srlinux"].Image)
	s.Require().Len(topology.Topology.Nodes, 3, "Generated YAML should contain two first-tier nodes and one second-tier node")
	s.Require().Contains(topology.Topology.Nodes, "clos-node1-1")
	s.Require().Contains(topology.Topology.Nodes, "clos-node1-2")
	s.Require().Contains(topology.Topology.Nodes, "clos-node2-1")
	s.Assert().Equal("clos-tier-1", topology.Topology.Nodes["clos-node1-1"].Group)
	s.Assert().Equal("ixrd3", topology.Topology.Nodes["clos-node1-1"].Type)
	s.Assert().Equal("clos-tier-2", topology.Topology.Nodes["clos-node2-1"].Group)
	s.Assert().Equal("ixrd2", topology.Topology.Nodes["clos-node2-1"].Type)
	s.Require().Len(topology.Topology.Links, 2, "Generated YAML should contain one link from each first-tier node to the second-tier node")
	for _, link := range topology.Topology.Links {
		s.Assert().Len(link.Endpoints, 2, "Generated links should have two endpoints")
	}

	if !s.T().Failed() {
		s.logSuccess("Successfully generated topology YAML for lab '%s'", generatedLabName)
	}
}

func (s *LabTopologySuite) TestGenerateTopologyDeploysMinimalLab() {
	generatedLabName := fmt.Sprintf("generated-min-%s", s.randomSuffix(5))
	defer s.cleanupLab(generatedLabName, true)

	s.logTest("Generating and deploying minimal topology for lab '%s'", generatedLabName)

	generateRequest := map[string]interface{}{
		"name":        generatedLabName,
		"defaultKind": "linux",
		"deploy":      true,
		"groupPrefix": "generated-tier",
		"images": map[string]string{
			"linux": "ghcr.io/srl-labs/network-multitool:latest",
		},
		"nodePrefix": "generated-node",
		"tiers": []map[string]interface{}{
			{
				"count": 1,
				"kind":  "linux",
			},
		},
	}

	jsonPayload := s.mustMarshal(generateRequest)

	generateURL := fmt.Sprintf("%s/api/v1/generate", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("POST", generateURL, s.apiUserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.DeployTimeout)
	s.Require().NoError(err, "Failed to execute generate-and-deploy topology request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 generating and deploying topology for '%s'. Body: %s", generatedLabName, string(bodyBytes))

	var generateResponse struct {
		Message       string                         `json:"message"`
		DeployOutput  map[string][]ClabContainerInfo `json:"deployOutput,omitempty"`
		SavedFilePath string                         `json:"savedFilePath,omitempty"`
	}
	err = json.Unmarshal(bodyBytes, &generateResponse)
	s.Require().NoError(err, "Failed to unmarshal generate topology response. Body: %s", string(bodyBytes))
	s.Assert().Contains(generateResponse.Message, "deployed successfully", "Response message should indicate successful deployment")
	s.Assert().NotEmpty(generateResponse.DeployOutput, "Response missing deployOutput for a deployed topology")
	s.Assert().NotEmpty(generateResponse.SavedFilePath, "Response missing savedFilePath")
	s.Require().Contains(generateResponse.DeployOutput, generatedLabName, "Deploy output doesn't reference the lab name")
	s.Require().NotEmpty(generateResponse.DeployOutput[generatedLabName], "Deploy output should contain at least one container")

	foundLinux := false
	for _, container := range generateResponse.DeployOutput[generatedLabName] {
		if container.Kind == "linux" {
			foundLinux = true
			break
		}
	}
	s.Assert().True(foundLinux, "Deploy output doesn't reference the linux node kind")

	if !s.T().Failed() {
		s.logSuccess("Successfully generated and deployed topology for lab '%s'", generatedLabName)
	}
}
