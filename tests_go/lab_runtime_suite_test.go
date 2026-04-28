package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type LabRuntimeSuite struct {
	BaseSuite

	apiUserHeaders http.Header
	labName        string
	containerName  string
	nodeName       string
}

func TestLabRuntimeSuite(t *testing.T) {
	suite.Run(t, new(LabRuntimeSuite))
}

func (s *LabRuntimeSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(apiUserToken)

	s.labName, _ = s.setupEphemeralLab()
	container := s.firstContainerInLab(s.labName, s.apiUserHeaders)
	s.containerName = container.Name
	s.nodeName = strings.TrimSpace(container.NodeName)
	if s.nodeName == "" {
		s.nodeName = s.containerName
	}
}

func (s *LabRuntimeSuite) TearDownSuite() {
	if s.labName != "" {
		s.cleanupLab(s.labName, true)
	}
	s.BaseSuite.TearDownSuite()
}

func (s *LabRuntimeSuite) nodeURL(action string) string {
	return fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/%s", s.cfg.APIURL, s.labName, url.PathEscape(s.nodeName), action)
}

func (s *LabRuntimeSuite) labURL(action string) string {
	return fmt.Sprintf("%s/api/v1/labs/%s/%s", s.cfg.APIURL, s.labName, action)
}

func (s *LabRuntimeSuite) postNodeAction(action string) {
	s.T().Helper()

	bodyBytes, statusCode, err := s.doRequest("POST", s.nodeURL(action), s.apiUserHeaders, nil, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for node %s. Body: %s", action, string(bodyBytes))
}

func (s *LabRuntimeSuite) postLabAction(action string) {
	s.T().Helper()

	bodyBytes, statusCode, err := s.doRequest("POST", s.labURL(action), s.apiUserHeaders, nil, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for lab %s. Body: %s", action, string(bodyBytes))
}

func (s *LabRuntimeSuite) TestBrowserPortsEndpoint() {
	bodyBytes, statusCode, err := s.doRequest("GET", s.nodeURL("browser-ports"), s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 getting browser ports. Body: %s", string(bodyBytes))

	var resp struct {
		NodeName      string `json:"nodeName"`
		ContainerName string `json:"containerName"`
		Ports         []struct {
			HostPort      int    `json:"hostPort"`
			ContainerPort int    `json:"containerPort"`
			Protocol      string `json:"protocol"`
		} `json:"ports"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Failed to unmarshal browser ports response. Body: %s", string(bodyBytes))
	s.Require().Equal(s.containerName, resp.ContainerName)
	s.Require().NotNil(resp.Ports)
}

func (s *LabRuntimeSuite) TestNodeStopStartPauseUnpauseEndpoints() {
	s.postNodeAction("stop")
	time.Sleep(500 * time.Millisecond)

	s.postNodeAction("start")
	time.Sleep(500 * time.Millisecond)

	s.postNodeAction("restart")
	time.Sleep(500 * time.Millisecond)

	s.postNodeAction("pause")
	time.Sleep(500 * time.Millisecond)

	s.postNodeAction("unpause")
}

func (s *LabRuntimeSuite) TestLabStartStopRestartEndpoints() {
	s.postLabAction("stop")
	time.Sleep(500 * time.Millisecond)

	s.postLabAction("start")
	time.Sleep(500 * time.Millisecond)

	s.postLabAction("restart")
}
