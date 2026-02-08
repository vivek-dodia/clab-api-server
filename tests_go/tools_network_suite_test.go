// tests_go/tools_network_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// ToolsNetworkSuite tests privileged network/tool endpoints (tx-offload, veth, vxlan).
type ToolsNetworkSuite struct {
	BaseSuite

	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header

	labName       string
	containerName string
}

func TestToolsNetworkSuite(t *testing.T) {
	suite.Run(t, new(ToolsNetworkSuite))
}

func (s *ToolsNetworkSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()

	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.apiUserToken)
	s.Require().NotEmpty(s.superuserToken)

	// Create an API-user owned lab to target container-based tools.
	s.labName = fmt.Sprintf("%s-tools-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", s.labName)
	s.logSetup("Creating tools test lab: %s", s.labName)
	bodyBytes, statusCode, err := s.createLab(s.apiUserHeaders, s.labName, topology, false, s.cfg.DeployTimeout)
	s.Require().NoError(err, "SETUP Failed: Could not create tools test lab")
	s.Require().Equal(http.StatusOK, statusCode, "SETUP Failed: Could not create tools test lab. Body: %s", string(bodyBytes))

	time.Sleep(s.cfg.StabilizePause)

	// Resolve a container name to use for tool calls.
	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, s.labName)
	inspectBytes, inspectStatus, inspectErr := s.doRequest("GET", inspectURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(inspectErr, "SETUP Failed: Could not inspect lab '%s'", s.labName)
	s.Require().Equal(http.StatusOK, inspectStatus, "SETUP Failed: Inspect lab returned non-OK. Body: %s", string(inspectBytes))

	var containers []ClabContainerInfo
	s.Require().NoError(json.Unmarshal(inspectBytes, &containers), "SETUP Failed: Could not decode inspect output. Body: %s", string(inspectBytes))
	s.Require().NotEmpty(containers, "SETUP Failed: No containers returned for lab '%s'", s.labName)
	s.containerName = containers[0].Name
	s.Require().NotEmpty(s.containerName)

	s.logSetup("Using container '%s' for tools tests", s.containerName)
}

func (s *ToolsNetworkSuite) TearDownSuite() {
	if s.labName != "" {
		s.logTeardown("Cleaning up tools test lab: %s", s.labName)
		s.cleanupLab(s.labName, true)
	}
	s.BaseSuite.TearDownSuite()
}

func (s *ToolsNetworkSuite) TestDisableTxOffloadForbiddenForAPIUser() {
	s.logTest("Calling disable-tx-offload as API user (expecting 403)")

	url := fmt.Sprintf("%s/api/v1/tools/disable-tx-offload", s.cfg.APIURL)
	payload := map[string]string{"containerName": s.containerName}
	body := bytes.NewBuffer(s.mustMarshal(payload))

	respBody, statusCode, err := s.doRequest("POST", url, s.apiUserHeaders, body, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected 403 for non-superuser disable-tx-offload. Body: %s", string(respBody))
}

func (s *ToolsNetworkSuite) TestDisableTxOffloadAsSuperuser() {
	s.logTest("Calling disable-tx-offload as superuser")

	url := fmt.Sprintf("%s/api/v1/tools/disable-tx-offload", s.cfg.APIURL)
	payload := map[string]string{"containerName": s.containerName}
	body := bytes.NewBuffer(s.mustMarshal(payload))

	respBody, statusCode, err := s.doRequest("POST", url, s.superuserHeaders, body, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for disable-tx-offload as superuser. Body: %s", string(respBody))
}

func (s *ToolsNetworkSuite) TestVethForbiddenForAPIUser() {
	s.logTest("Calling veth create as API user (expecting 403)")

	url := fmt.Sprintf("%s/api/v1/tools/veth", s.cfg.APIURL)
	payload := map[string]interface{}{
		"aEndpoint": "host:dummy0",
		"bEndpoint": s.containerName + ":eth10",
		"mtu":       1500,
	}
	body := bytes.NewBuffer(s.mustMarshal(payload))

	respBody, statusCode, err := s.doRequest("POST", url, s.apiUserHeaders, body, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected 403 for non-superuser veth create. Body: %s", string(respBody))
}

func (s *ToolsNetworkSuite) TestVxlanCreateForbiddenForAPIUser() {
	s.logTest("Calling vxlan create as API user (expecting 403)")

	url := fmt.Sprintf("%s/api/v1/tools/vxlan", s.cfg.APIURL)
	payload := map[string]interface{}{
		"remote": "127.0.0.1",
		"link":   "dummy0",
		"id":     10,
		"port":   14789,
	}
	body := bytes.NewBuffer(s.mustMarshal(payload))

	respBody, statusCode, err := s.doRequest("POST", url, s.apiUserHeaders, body, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected 403 for non-superuser vxlan create. Body: %s", string(respBody))
}

func (s *ToolsNetworkSuite) TestVxlanDeleteForbiddenForAPIUser() {
	s.logTest("Calling vxlan delete as API user (expecting 403)")

	url := fmt.Sprintf("%s/api/v1/tools/vxlan?prefix=vx-", s.cfg.APIURL)
	respBody, statusCode, err := s.doRequest("DELETE", url, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected 403 for non-superuser vxlan delete. Body: %s", string(respBody))
}

func (s *ToolsNetworkSuite) TestVethAndVxlanLifecycleAsSuperuser() {
	s.logTest("Creating veth (host<->container), creating vxlan, then deleting vxlan as superuser")

	linkName := "gtvx" + s.randomSuffix(5) // ensure <= 15 chars (vx-<link> must also fit)
	containerIface := "eth10"

	// 1) Create veth pair between host and container. The host-side iface will be "linkName".
	vethURL := fmt.Sprintf("%s/api/v1/tools/veth", s.cfg.APIURL)
	vethPayload := map[string]interface{}{
		"aEndpoint": fmt.Sprintf("host:%s", linkName),
		"bEndpoint": fmt.Sprintf("%s:%s", s.containerName, containerIface),
		"mtu":       1500,
	}
	vethBody := bytes.NewBuffer(s.mustMarshal(vethPayload))
	vethRespBody, vethStatus, vethErr := s.doRequest("POST", vethURL, s.superuserHeaders, vethBody, s.cfg.RequestTimeout)
	s.Require().NoError(vethErr)
	s.Require().Equal(http.StatusOK, vethStatus, "Expected 200 for veth create. Body: %s", string(vethRespBody))

	// 2) Create vxlan stitched to the host interface.
	vxlanURL := fmt.Sprintf("%s/api/v1/tools/vxlan", s.cfg.APIURL)
	vxlanPayload := map[string]interface{}{
		"remote": "127.0.0.1",
		"link":   linkName,
		"id":     10,
		"port":   14789,
	}
	vxlanBody := bytes.NewBuffer(s.mustMarshal(vxlanPayload))
	vxlanRespBody, vxlanStatus, vxlanErr := s.doRequest("POST", vxlanURL, s.superuserHeaders, vxlanBody, s.cfg.RequestTimeout)
	s.Require().NoError(vxlanErr)
	s.Require().Equal(http.StatusOK, vxlanStatus, "Expected 200 for vxlan create. Body: %s", string(vxlanRespBody))

	// 3) Delete the created vxlan interface (named "vx-<linkName>").
	deleteURL := fmt.Sprintf("%s/api/v1/tools/vxlan?prefix=%s", s.cfg.APIURL, "vx-"+linkName)
	deleteRespBody, deleteStatus, deleteErr := s.doRequest("DELETE", deleteURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(deleteErr)
	s.Require().Equal(http.StatusOK, deleteStatus, "Expected 200 for vxlan delete. Body: %s", string(deleteRespBody))

	var resp struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(deleteRespBody, &resp); err == nil && resp.Message != "" {
		s.Assert().Contains(resp.Message, "vx-"+linkName, "Expected delete response to reference deleted vxlan interface name")
	}

	if !s.T().Failed() {
		s.logSuccess("veth + vxlan lifecycle completed successfully (link=%s)", linkName)
	}
}
