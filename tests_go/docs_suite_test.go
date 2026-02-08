// tests_go/docs_suite_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

// DocsSuite tests public documentation endpoints (swagger/redoc).
type DocsSuite struct {
	BaseSuite
}

func TestDocsSuite(t *testing.T) {
	suite.Run(t, new(DocsSuite))
}

func (s *DocsSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
}

func (s *DocsSuite) TestSwaggerUIIndexHTML() {
	s.logTest("Fetching swagger UI index page")

	url := fmt.Sprintf("%s/swagger/index.html", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", url, nil, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for swagger UI. Body: %s", string(bodyBytes))

	s.Assert().NotEmpty(bodyBytes, "Expected swagger UI page content to be non-empty")
	// Avoid strict string matching; just sanity-check it's HTML-ish.
	s.Assert().True(strings.Contains(strings.ToLower(string(bodyBytes)), "<html"), "Expected HTML response for swagger UI")
}

func (s *DocsSuite) TestSwaggerDocJSON() {
	s.logTest("Fetching swagger doc.json")

	url := fmt.Sprintf("%s/swagger/doc.json", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", url, nil, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for swagger doc.json. Body: %s", string(bodyBytes))

	var doc map[string]interface{}
	s.Require().NoError(json.Unmarshal(bodyBytes, &doc), "Expected JSON swagger document. Body: %s", string(bodyBytes))
	// swaggo typically emits Swagger 2.0 with top-level "swagger": "2.0".
	_, hasSwagger := doc["swagger"]
	_, hasOpenAPI := doc["openapi"]
	s.Assert().True(hasSwagger || hasOpenAPI, "Expected swagger/openapi field in doc.json")
}

func (s *DocsSuite) TestRedocPage() {
	s.logTest("Fetching redoc page")

	url := fmt.Sprintf("%s/redoc", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", url, nil, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for redoc. Body: %s", string(bodyBytes))

	s.Assert().NotEmpty(bodyBytes, "Expected redoc page content to be non-empty")
	s.Assert().Contains(string(bodyBytes), `<redoc spec-url="/swagger/doc.json">`, "Expected redoc HTML to reference swagger spec URL")
}
