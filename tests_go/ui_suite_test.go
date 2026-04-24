package tests_go

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/suite"
)

type UISuite struct {
	BaseSuite

	apiUserHeaders   http.Header
	superuserHeaders http.Header
}

func TestUISuite(t *testing.T) {
	suite.Run(t, new(UISuite))
}

func (s *UISuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserHeaders, s.superuserHeaders = s.loginBothUsers()
}

type customNodesResponse struct {
	CustomNodes []map[string]interface{} `json:"customNodes"`
	DefaultNode string                   `json:"defaultNode"`
}

type iconListResponse struct {
	Icons []struct {
		Name    string `json:"name"`
		Source  string `json:"source"`
		DataURI string `json:"dataUri"`
		Format  string `json:"format"`
	} `json:"icons"`
}

func (s *UISuite) getCustomNodes(headers http.Header) customNodesResponse {
	s.T().Helper()

	url := fmt.Sprintf("%s/api/v1/ui/custom-nodes", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", url, headers, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 listing custom nodes. Body: %s", string(bodyBytes))

	var resp customNodesResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Failed to unmarshal custom nodes response. Body: %s", string(bodyBytes))
	return resp
}

func (s *UISuite) putCustomNodes(headers http.Header, nodes []map[string]interface{}) customNodesResponse {
	s.T().Helper()

	payload := map[string]interface{}{"customNodes": nodes}
	url := fmt.Sprintf("%s/api/v1/ui/custom-nodes", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("PUT", url, headers, bytes.NewBuffer(s.mustMarshal(payload)), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 replacing custom nodes. Body: %s", string(bodyBytes))

	var resp customNodesResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Failed to unmarshal custom nodes response. Body: %s", string(bodyBytes))
	return resp
}

func (s *UISuite) nodeNames(nodes []map[string]interface{}) map[string]struct{} {
	names := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if name, ok := node["name"].(string); ok {
			names[name] = struct{}{}
		}
	}
	return names
}

func (s *UISuite) TestCustomNodesPersistUpdateDeleteAndIsolateByUser() {
	apiOriginal := s.getCustomNodes(s.apiUserHeaders)
	superuserOriginal := s.getCustomNodes(s.superuserHeaders)
	defer s.putCustomNodes(s.apiUserHeaders, apiOriginal.CustomNodes)
	defer s.putCustomNodes(s.superuserHeaders, superuserOriginal.CustomNodes)

	apiNodeName := "gotest-api-node-" + s.randomSuffix(6)
	superuserNodeName := "gotest-su-node-" + s.randomSuffix(6)
	renamedAPIName := apiNodeName + "-renamed"

	s.logTest("Replacing API user's custom node set")
	apiResp := s.putCustomNodes(s.apiUserHeaders, []map[string]interface{}{
		{
			"name":             apiNodeName,
			"kind":             "linux",
			"image":            "ghcr.io/srl-labs/network-multitool:latest",
			"icon":             "client",
			"baseName":         "gotest",
			"interfacePattern": "eth{n}",
			"setDefault":       true,
		},
	})
	s.Require().Equal(apiNodeName, apiResp.DefaultNode)
	s.Require().Contains(s.nodeNames(apiResp.CustomNodes), apiNodeName)

	s.logTest("Verifying custom node state is isolated from the superuser account")
	superuserView := s.getCustomNodes(s.superuserHeaders)
	s.Require().NotContains(s.nodeNames(superuserView.CustomNodes), apiNodeName)

	s.putCustomNodes(s.superuserHeaders, []map[string]interface{}{
		{
			"name":             superuserNodeName,
			"kind":             "linux",
			"image":            "ghcr.io/srl-labs/network-multitool:latest",
			"icon":             "server",
			"baseName":         "gotestsu",
			"interfacePattern": "eth{n}",
			"setDefault":       true,
		},
	})
	apiView := s.getCustomNodes(s.apiUserHeaders)
	s.Require().NotContains(s.nodeNames(apiView.CustomNodes), superuserNodeName)

	s.logTest("Updating a custom node through the single-node save endpoint")
	savePayload := map[string]interface{}{
		"oldName":          apiNodeName,
		"name":             renamedAPIName,
		"kind":             "linux",
		"image":            "ghcr.io/srl-labs/network-multitool:latest",
		"icon":             "cloud",
		"baseName":         "renamed",
		"interfacePattern": "eth{n}",
		"setDefault":       false,
	}
	saveURL := fmt.Sprintf("%s/api/v1/ui/custom-nodes", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("POST", saveURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(savePayload)), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 saving custom node. Body: %s", string(bodyBytes))

	var saveResp customNodesResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &saveResp))
	names := s.nodeNames(saveResp.CustomNodes)
	s.Require().Contains(names, renamedAPIName)
	s.Require().NotContains(names, apiNodeName)

	s.logTest("Setting and deleting a custom node")
	defaultURL := fmt.Sprintf("%s/api/v1/ui/custom-nodes/default", s.cfg.APIURL)
	bodyBytes, statusCode, err = s.doRequest("POST", defaultURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string]string{"name": renamedAPIName})), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 setting default custom node. Body: %s", string(bodyBytes))

	var defaultResp customNodesResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &defaultResp))
	s.Require().Equal(renamedAPIName, defaultResp.DefaultNode)

	deleteURL := fmt.Sprintf("%s/api/v1/ui/custom-nodes/%s", s.cfg.APIURL, renamedAPIName)
	bodyBytes, statusCode, err = s.doRequest("DELETE", deleteURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 deleting custom node. Body: %s", string(bodyBytes))

	var deleteResp customNodesResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &deleteResp))
	s.Require().NotContains(s.nodeNames(deleteResp.CustomNodes), renamedAPIName)
}

func (s *UISuite) TestCustomNodeValidationRejectsInvalidPayload() {
	url := fmt.Sprintf("%s/api/v1/ui/custom-nodes", s.cfg.APIURL)
	payload := map[string]interface{}{
		"name": "gotest-invalid-" + s.randomSuffix(5),
	}

	bodyBytes, statusCode, err := s.doRequest("POST", url, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(payload)), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid custom node payload. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "kind")
}

func (s *UISuite) TestGlobalIconUploadListDeleteAndIsolateByUser() {
	iconBaseName := "gotest-icon-" + s.randomSuffix(6)
	uploadURL := fmt.Sprintf("%s/api/v1/ui/icons", s.cfg.APIURL)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><rect width="16" height="16" fill="#123456"/></svg>`)
	payload := map[string]string{
		"fileName":    iconBaseName + ".svg",
		"contentType": "image/svg+xml",
		"dataBase64":  base64.StdEncoding.EncodeToString(svg),
	}

	bodyBytes, statusCode, err := s.doRequest("POST", uploadURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(payload)), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 uploading icon. Body: %s", string(bodyBytes))

	var uploadResp struct {
		Success  bool   `json:"success"`
		IconName string `json:"iconName"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &uploadResp), "Failed to unmarshal icon upload response. Body: %s", string(bodyBytes))
	s.Require().True(uploadResp.Success)
	s.Require().NotEmpty(uploadResp.IconName)

	deleteURL := fmt.Sprintf("%s/api/v1/ui/icons/%s", s.cfg.APIURL, uploadResp.IconName)
	defer func() {
		_, _, _ = s.doRequest("DELETE", deleteURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	}()

	listURL := fmt.Sprintf("%s/api/v1/ui/icons", s.cfg.APIURL)
	bodyBytes, statusCode, err = s.doRequest("GET", listURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 listing icons. Body: %s", string(bodyBytes))

	var listResp iconListResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &listResp), "Failed to unmarshal icon list response. Body: %s", string(bodyBytes))
	found := false
	for _, icon := range listResp.Icons {
		if icon.Name == uploadResp.IconName {
			found = true
			s.Require().Equal("global", icon.Source)
			s.Require().Equal("svg", icon.Format)
			s.Require().NotEmpty(icon.DataURI)
		}
	}
	s.Require().True(found, "Expected uploaded icon %q in API user's icon list", uploadResp.IconName)

	bodyBytes, statusCode, err = s.doRequest("GET", listURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 listing superuser icons. Body: %s", string(bodyBytes))
	var superuserList iconListResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &superuserList), "Failed to unmarshal superuser icon list response. Body: %s", string(bodyBytes))
	for _, icon := range superuserList.Icons {
		s.Require().NotEqual(uploadResp.IconName, icon.Name, "Uploaded API user icon should not appear in superuser icon list")
	}

	bodyBytes, statusCode, err = s.doRequest("DELETE", deleteURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 deleting icon. Body: %s", string(bodyBytes))

	bodyBytes, statusCode, err = s.doRequest("GET", listURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 listing icons after delete. Body: %s", string(bodyBytes))
	var postDeleteList iconListResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &postDeleteList), "Failed to unmarshal post-delete icon list response. Body: %s", string(bodyBytes))
	for _, icon := range postDeleteList.Icons {
		s.Require().NotEqual(uploadResp.IconName, icon.Name, "Deleted icon should not remain in icon list")
	}
}

func (s *UISuite) TestGlobalIconValidationRejectsBadPayload() {
	url := fmt.Sprintf("%s/api/v1/ui/icons", s.cfg.APIURL)
	payload := map[string]string{
		"fileName":   "gotest-invalid.txt",
		"dataBase64": "not-base64",
	}

	bodyBytes, statusCode, err := s.doRequest("POST", url, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(payload)), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for unsupported icon upload. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Only SVG and PNG")
}

func (s *UISuite) TestLabIconListAndReconcile() {
	labName := "gotest-ui-icons-" + s.randomSuffix(6)
	topologyPath := labName + ".clab.yml"
	iconBaseName := "gotest-lab-icon-" + s.randomSuffix(6)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><circle cx="8" cy="8" r="7" fill="#654321"/></svg>`)

	topologyURL, _ := url.Parse(fmt.Sprintf("%s/api/v1/labs/%s/topology/file", s.cfg.APIURL, labName))
	topologyQuery := topologyURL.Query()
	topologyQuery.Set("path", topologyPath)
	topologyURL.RawQuery = topologyQuery.Encode()
	defer func() {
		_, _, _ = s.doRequest("DELETE", topologyURL.String(), s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	}()

	topologyBody := fmt.Sprintf("name: %s\ntopology:\n  nodes:\n    srl1:\n      kind: linux\n", labName)
	bodyBytes, statusCode, err := s.doRequest("PUT", topologyURL.String(), s.apiUserHeaders, bytes.NewBufferString(topologyBody), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 creating lab workspace file. Body: %s", string(bodyBytes))

	uploadURL := fmt.Sprintf("%s/api/v1/ui/icons", s.cfg.APIURL)
	bodyBytes, statusCode, err = s.doRequest("POST", uploadURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string]string{
		"fileName":   iconBaseName + ".svg",
		"dataBase64": base64.StdEncoding.EncodeToString(svg),
	})), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 uploading global icon. Body: %s", string(bodyBytes))

	var uploadResp struct {
		IconName string `json:"iconName"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &uploadResp), "Failed to unmarshal upload response. Body: %s", string(bodyBytes))
	s.Require().NotEmpty(uploadResp.IconName)
	defer func() {
		_, _, _ = s.doRequest("DELETE", fmt.Sprintf("%s/api/v1/ui/icons/%s", s.cfg.APIURL, uploadResp.IconName), s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	}()

	reconcileURL := fmt.Sprintf("%s/api/v1/labs/%s/ui/icons/reconcile", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err = s.doRequest("POST", reconcileURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string][]string{
		"usedIcons": []string{uploadResp.IconName},
	})), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 reconciling lab icons. Body: %s", string(bodyBytes))
	defer func() {
		_, _, _ = s.doRequest("POST", reconcileURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string][]string{"usedIcons": []string{}})), s.cfg.RequestTimeout)
	}()

	listURL := fmt.Sprintf("%s/api/v1/labs/%s/ui/icons", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err = s.doRequest("GET", listURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 listing lab icons. Body: %s", string(bodyBytes))

	var listResp iconListResponse
	s.Require().NoError(json.Unmarshal(bodyBytes, &listResp), "Failed to unmarshal lab icon list. Body: %s", string(bodyBytes))
	found := false
	for _, icon := range listResp.Icons {
		if icon.Name == uploadResp.IconName {
			found = true
			s.Require().Equal("workspace", icon.Source)
			s.Require().Equal("svg", icon.Format)
			s.Require().NotEmpty(icon.DataURI)
		}
	}
	s.Require().True(found, "Expected reconciled lab icon %q in lab icon list", uploadResp.IconName)
}
