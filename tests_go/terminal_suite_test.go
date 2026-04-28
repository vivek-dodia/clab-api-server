package tests_go

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/suite"
)

type TerminalSuite struct {
	BaseSuite

	apiUserHeaders   http.Header
	superuserHeaders http.Header
	labName          string
	containerName    string
}

func TestTerminalSuite(t *testing.T) {
	suite.Run(t, new(TerminalSuite))
}

func (s *TerminalSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserHeaders, s.superuserHeaders = s.loginBothUsers()

	s.labName, _ = s.setupEphemeralLab()
	container := s.firstContainerInLab(s.labName, s.apiUserHeaders)
	s.containerName = container.Name
}

func (s *TerminalSuite) TearDownSuite() {
	if s.labName != "" {
		s.cleanupLab(s.labName, true)
	}
	s.BaseSuite.TearDownSuite()
}

func (s *TerminalSuite) terminalCreateURL(labName, containerName string) string {
	return fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/terminal-sessions", s.cfg.APIURL, labName, url.PathEscape(containerName))
}

func (s *TerminalSuite) createTerminalSession(headers http.Header, labName, containerName, protocol string) string {
	s.T().Helper()

	payload := map[string]interface{}{
		"protocol": protocol,
		"cols":     80,
		"rows":     24,
	}
	bodyBytes, statusCode, err := s.doRequest(
		"POST",
		s.terminalCreateURL(labName, containerName),
		headers,
		bytes.NewBuffer(s.mustMarshal(payload)),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 creating terminal session. Body: %s", string(bodyBytes))

	var resp struct {
		SessionID string `json:"sessionId"`
		Protocol  string `json:"protocol"`
		State     string `json:"state"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Failed to unmarshal terminal create response. Body: %s", string(bodyBytes))
	s.Require().NotEmpty(resp.SessionID)
	s.Require().Equal(protocol, resp.Protocol)
	s.Require().NotEmpty(resp.State)
	return resp.SessionID
}

func (s *TerminalSuite) terminateTerminalSession(headers http.Header, sessionID string) (int, []byte) {
	s.T().Helper()

	termURL := fmt.Sprintf("%s/api/v1/terminal-sessions/%s", s.cfg.APIURL, sessionID)
	bodyBytes, statusCode, err := s.doRequest("DELETE", termURL, headers, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	return statusCode, bodyBytes
}

func (s *TerminalSuite) TestCreateGetTerminateShellSession() {
	s.logTest("Creating shell terminal session for '%s'", s.containerName)

	sessionID := s.createTerminalSession(s.apiUserHeaders, s.labName, s.containerName, "shell")
	defer s.terminateTerminalSession(s.apiUserHeaders, sessionID)

	getURL := fmt.Sprintf("%s/api/v1/terminal-sessions/%s", s.cfg.APIURL, sessionID)
	bodyBytes, statusCode, err := s.doRequest("GET", getURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 getting terminal session. Body: %s", string(bodyBytes))

	var info struct {
		SessionID string `json:"sessionId"`
		Username  string `json:"username"`
		LabName   string `json:"labName"`
		NodeName  string `json:"nodeName"`
		Protocol  string `json:"protocol"`
		State     string `json:"state"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &info), "Failed to unmarshal terminal info. Body: %s", string(bodyBytes))
	s.Require().Equal(sessionID, info.SessionID)
	s.Require().Equal(s.cfg.APIUserUser, info.Username)
	s.Require().Equal(s.labName, info.LabName)
	s.Require().Equal("shell", info.Protocol)
	s.Require().NotEmpty(info.NodeName)

	statusCode, bodyBytes = s.terminateTerminalSession(s.apiUserHeaders, sessionID)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 terminating own terminal session. Body: %s", string(bodyBytes))
}

func (s *TerminalSuite) TestTerminalSessionWebSocketStreamConnects() {
	sessionID := s.createTerminalSession(s.apiUserHeaders, s.labName, s.containerName, "shell")
	defer s.terminateTerminalSession(s.apiUserHeaders, sessionID)

	streamURL := fmt.Sprintf("%s/api/v1/terminal-sessions/%s/stream", s.cfg.APIURL, sessionID)
	streamURL = strings.Replace(streamURL, "http://", "ws://", 1)
	streamURL = strings.Replace(streamURL, "https://", "wss://", 1)

	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Test client accepts local self-signed certificates.
	dialer.HandshakeTimeout = s.cfg.RequestTimeout

	conn, resp, err := dialer.Dial(streamURL, s.apiUserHeaders)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	s.Require().NoError(err, "Expected terminal stream websocket upgrade to succeed")
	defer conn.Close()

	var ready map[string]interface{}
	s.Require().NoError(conn.ReadJSON(&ready), "Expected ready message from terminal stream")
	s.Require().Equal("ready", ready["type"])
	s.Require().Equal(sessionID, ready["sessionId"])

	s.Require().NoError(conn.WriteJSON(map[string]string{"type": "close"}))
}

func (s *TerminalSuite) TestTerminalSessionRejectsNonOwnerAccess() {
	suLabName, suHeaders := s.setupSuperuserLab()
	defer s.cleanupLab(suLabName, true)

	container := s.firstContainerInLab(suLabName, suHeaders)
	sessionID := s.createTerminalSession(suHeaders, suLabName, container.Name, "shell")
	defer s.terminateTerminalSession(suHeaders, sessionID)

	getURL := fmt.Sprintf("%s/api/v1/terminal-sessions/%s", s.cfg.APIURL, sessionID)
	bodyBytes, statusCode, err := s.doRequest("GET", getURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusNotFound, statusCode, "Expected 404 for non-owner terminal session read. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "not owned")

	statusCode, bodyBytes = s.terminateTerminalSession(s.apiUserHeaders, sessionID)
	s.Require().Equal(http.StatusNotFound, statusCode, "Expected 404 for non-owner terminal session termination. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "not owned")
}

func (s *TerminalSuite) TestTerminalSessionRejectsInvalidProtocol() {
	bodyBytes, statusCode, err := s.doRequest(
		"POST",
		s.terminalCreateURL(s.labName, s.containerName),
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{
			"protocol": "invalid-protocol",
			"cols":     80,
			"rows":     24,
		})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid terminal protocol. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "unsupported terminal protocol")
}

func (s *TerminalSuite) TestTerminalSessionRejectsMismatchedLabNode() {
	bodyBytes, statusCode, err := s.doRequest(
		"POST",
		s.terminalCreateURL(s.labName, "clab-otherlab-node1"),
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{"protocol": "shell"})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for mismatched terminal lab/node. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "does not belong")
}
