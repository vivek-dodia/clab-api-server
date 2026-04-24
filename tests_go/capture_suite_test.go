package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/suite"
)

type CaptureSuite struct {
	BaseSuite

	apiUserHeaders   http.Header
	superuserHeaders http.Header
	labName          string
	containerName    string
}

func TestCaptureSuite(t *testing.T) {
	suite.Run(t, new(CaptureSuite))
}

func (s *CaptureSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserHeaders, s.superuserHeaders = s.loginBothUsers()

	s.labName, _ = s.setupEphemeralLab()
	container := s.firstContainerInLab(s.labName, s.apiUserHeaders)
	s.containerName = container.Name
}

func (s *CaptureSuite) TearDownSuite() {
	_, _, _ = s.doRequest("DELETE", fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions", s.cfg.APIURL), s.superuserHeaders, nil, s.cfg.RequestTimeout)
	if s.labName != "" {
		s.cleanupLab(s.labName, true)
	}
	s.BaseSuite.TearDownSuite()
}

func (s *CaptureSuite) TestEdgeSharkStatusAndPrivileges() {
	statusURL := fmt.Sprintf("%s/api/v1/tools/edgeshark/status", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", statusURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 getting EdgeShark status. Body: %s", string(bodyBytes))

	var statusResp struct {
		Running        bool   `json:"running"`
		Version        string `json:"version"`
		PacketflixPort int    `json:"packetflixPort"`
		Runtime        string `json:"runtime"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &statusResp), "Failed to unmarshal EdgeShark status. Body: %s", string(bodyBytes))
	s.Require().Greater(statusResp.PacketflixPort, 0)
	s.Require().NotEmpty(statusResp.Runtime)

	for _, endpoint := range []string{"install", "uninstall"} {
		actionURL := fmt.Sprintf("%s/api/v1/tools/edgeshark/%s", s.cfg.APIURL, endpoint)
		bodyBytes, statusCode, err = s.doRequest("POST", actionURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusForbidden, statusCode, "Expected 403 for API user EdgeShark %s. Body: %s", endpoint, string(bodyBytes))
		s.assertJSONError(bodyBytes, "Superuser privileges required")
	}
}

func (s *CaptureSuite) TestPacketflixCaptureValidationAndEnvironmentTolerantSuccess() {
	packetflixURL := fmt.Sprintf("%s/api/v1/labs/%s/capture/packetflix", s.cfg.APIURL, s.labName)

	bodyBytes, statusCode, err := s.doRequest(
		"POST",
		packetflixURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{"targets": []interface{}{}})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for empty capture targets. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Targets")

	bodyBytes, statusCode, err = s.doRequest(
		"POST",
		packetflixURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{
			"targets": []map[string]string{
				{"containerName": s.containerName, "interfaceName": "bad iface"},
			},
		})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid capture interface. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid interface name")

	bodyBytes, statusCode, err = s.doRequest(
		"POST",
		packetflixURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{
			"targets": []map[string]string{
				{"containerName": s.containerName, "interfaceName": "eth1"},
				{"containerName": s.containerName, "interfaceName": "eth1"},
			},
		})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)

	switch statusCode {
	case http.StatusOK:
		var resp struct {
			Captures []struct {
				ContainerName  string   `json:"containerName"`
				InterfaceNames []string `json:"interfaceNames"`
				PacketflixURI  string   `json:"packetflixUri"`
			} `json:"captures"`
		}
		s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Failed to unmarshal packetflix response. Body: %s", string(bodyBytes))
		s.Require().Len(resp.Captures, 1)
		s.Require().Equal(s.containerName, resp.Captures[0].ContainerName)
		s.Require().Equal([]string{"eth1"}, resp.Captures[0].InterfaceNames)
		s.Require().Contains(resp.Captures[0].PacketflixURI, "packetflix:ws://")
	case http.StatusServiceUnavailable:
		s.assertJSONError(bodyBytes, "Edgeshark is not running")
	default:
		s.Require().Failf("unexpected packetflix status", "status=%d body=%s", statusCode, string(bodyBytes))
	}
}

func (s *CaptureSuite) TestWiresharkVncSessionErrorsAndCloseAll() {
	unknownSessionID := "missing-session-" + s.randomSuffix(6)

	readyURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions/%s/ready", s.cfg.APIURL, unknownSessionID)
	bodyBytes, statusCode, err := s.doRequest("GET", readyURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusNotFound, statusCode, "Expected 404 for unknown capture session readiness. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "capture session not found")

	deleteURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions/%s", s.cfg.APIURL, unknownSessionID)
	bodyBytes, statusCode, err = s.doRequest("DELETE", deleteURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusNotFound, statusCode, "Expected 404 deleting unknown capture session. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "capture session not found")

	proxyURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions/%s/vnc/%s", s.cfg.APIURL, unknownSessionID, url.PathEscape("index.html"))
	bodyBytes, statusCode, err = s.doRequest("GET", proxyURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusNotFound, statusCode, "Expected 404 proxying unknown capture session. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "capture session not found")

	closeAllURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions", s.cfg.APIURL)
	bodyBytes, statusCode, err = s.doRequest("DELETE", closeAllURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 closing capture sessions. Body: %s", string(bodyBytes))

	var closeResp struct {
		Message string `json:"message"`
		Closed  int    `json:"closed"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &closeResp), "Failed to unmarshal close-all response. Body: %s", string(bodyBytes))
	s.Require().GreaterOrEqual(closeResp.Closed, 0)
	s.Require().NotEmpty(closeResp.Message)
}

func (s *CaptureSuite) TestWiresharkVncSessionCreateIsEnvironmentTolerant() {
	createURL := fmt.Sprintf("%s/api/v1/labs/%s/capture/wireshark-vnc-sessions", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err := s.doRequest(
		"POST",
		createURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{
			"theme": "dark",
			"targets": []map[string]string{
				{"containerName": s.containerName, "interfaceName": "eth1"},
			},
		})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)

	switch statusCode {
	case http.StatusOK:
		var resp struct {
			Sessions []struct {
				SessionID     string `json:"sessionId"`
				LabName       string `json:"labName"`
				ContainerName string `json:"containerName"`
				VncPath       string `json:"vncPath"`
			} `json:"sessions"`
		}
		s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Failed to unmarshal VNC session response. Body: %s", string(bodyBytes))
		s.Require().Len(resp.Sessions, 1)
		s.Require().NotEmpty(resp.Sessions[0].SessionID)
		s.Require().Equal(s.labName, resp.Sessions[0].LabName)
		s.Require().Equal(s.containerName, resp.Sessions[0].ContainerName)
		s.Require().NotEmpty(resp.Sessions[0].VncPath)

		deleteURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions/%s", s.cfg.APIURL, resp.Sessions[0].SessionID)
		deleteBody, deleteStatus, deleteErr := s.doRequest("DELETE", deleteURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
		s.Require().NoError(deleteErr)
		s.Require().Equal(http.StatusOK, deleteStatus, "Expected 200 deleting created VNC capture session. Body: %s", string(deleteBody))
	case http.StatusServiceUnavailable:
		s.assertJSONError(bodyBytes, "Edgeshark is not running")
	default:
		s.Require().Failf("unexpected VNC capture create status", "status=%d body=%s", statusCode, string(bodyBytes))
	}
}
