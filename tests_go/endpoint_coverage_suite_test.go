package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

type EndpointCoverageSuite struct {
	BaseSuite

	apiUserHeaders http.Header
	labName        string
}

func TestEndpointCoverageSuite(t *testing.T) {
	suite.Run(t, new(EndpointCoverageSuite))
}

func (s *EndpointCoverageSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(apiUserToken)

	s.labName, _ = s.setupEphemeralLab()
}

func (s *EndpointCoverageSuite) TearDownSuite() {
	if s.labName != "" {
		s.cleanupLab(s.labName, true)
	}
	s.BaseSuite.TearDownSuite()
}

func (s *EndpointCoverageSuite) TestRootEndpoint() {
	bodyBytes, statusCode, err := s.doRequest("GET", s.cfg.APIURL+"/", nil, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for root endpoint. Body: %s", string(bodyBytes))

	var resp map[string]interface{}
	s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Expected root endpoint to return JSON. Body: %s", string(bodyBytes))
	s.Require().Contains(resp, "api_base_path")
}

func (s *EndpointCoverageSuite) TestImportTopologyFromURLRejectsUnsupportedSource() {
	importURL := fmt.Sprintf("%s/api/v1/labs/topology/import-from-url", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest(
		"POST",
		importURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]string{"topologySourceUrl": "https://example.com/not-supported.git"})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for unsupported topology import source. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Only GitHub and GitLab")
}

func (s *EndpointCoverageSuite) TestShareToolRoutesValidateAction() {
	for _, tool := range []string{"sshx", "gotty"} {
		actionURL := fmt.Sprintf("%s/api/v1/labs/%s/%s/not-an-action", s.cfg.APIURL, s.labName, tool)
		bodyBytes, statusCode, err := s.doRequest("POST", actionURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid %s action. Body: %s", tool, string(bodyBytes))
		s.assertJSONError(bodyBytes, "Invalid action")
	}

	gottyURL := fmt.Sprintf("%s/api/v1/labs/%s/gotty/attach?port=not-a-port", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err := s.doRequest("POST", gottyURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid gotty port. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid gotty port")
}

func (s *EndpointCoverageSuite) TestGracefulTimeoutValidation() {
	redeployURL := fmt.Sprintf("%s/api/v1/labs/%s?gracefulTimeout=5s", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err := s.doRequest("PUT", redeployURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 when gracefulTimeout is used without graceful=true. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "gracefulTimeout")

	destroyURL := fmt.Sprintf("%s/api/v1/labs/%s?graceful=true&gracefulTimeout=0s", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err = s.doRequest("DELETE", destroyURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for nonpositive gracefulTimeout. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid 'gracefulTimeout'")
}

func (s *EndpointCoverageSuite) TestFcliAndDrawioRoutesValidateInput() {
	fcliURL := fmt.Sprintf("%s/api/v1/labs/%s/fcli", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err := s.doRequest("POST", fcliURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string]string{"command": ""})), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for empty fcli command. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid request body")

	drawioURL := fmt.Sprintf("%s/api/v1/labs/%s/graph/drawio", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err = s.doRequest("POST", drawioURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string]string{"layout": "diagonal"})), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid drawio layout. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid layout")
}
