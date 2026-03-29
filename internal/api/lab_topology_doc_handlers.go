package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
)

func resolveRunningLabDocPath(c *gin.Context, docType string) (string, string, error) {
	username := c.GetString("username")
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return "", "", fmt.Errorf("invalid lab name")
	}

	topologyPath, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return "", "", ownerCheckErr
	}
	if strings.TrimSpace(topologyPath) == "" {
		err := fmt.Errorf("topology path for lab '%s' is empty", labName)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return "", "", err
	}

	docPath := filepath.Clean(topologyPath)
	switch docType {
	case "yaml":
		// keep topology path
	case "annotations":
		docPath = docPath + ".annotations.json"
	default:
		err := fmt.Errorf("invalid topology document type")
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return "", "", err
	}

	ownerUsername := username
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if info, exists, lookupErr := getLabInfo(ctx, username, labName); lookupErr == nil && exists && info != nil && info.Owner != "" {
		ownerUsername = info.Owner
	}

	return docPath, ownerUsername, nil
}

func readRunningLabDoc(c *gin.Context, docType string) {
	docPath, _, err := resolveRunningLabDocPath(c, docType)
	if err != nil {
		return
	}

	content, readErr := os.ReadFile(docPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "File not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: readErr.Error()})
		return
	}

	c.Data(http.StatusOK, "text/plain; charset=utf-8", content)
}

func writeRunningLabDoc(c *gin.Context, docType string) {
	docPath, ownerUsername, err := resolveRunningLabDocPath(c, docType)
	if err != nil {
		return
	}

	body, readErr := io.ReadAll(c.Request.Body)
	if readErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Failed to read request body"})
		return
	}

	targetDir := filepath.Dir(docPath)
	if mkdirErr := os.MkdirAll(targetDir, 0750); mkdirErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure lab directory: %s", mkdirErr.Error())})
		return
	}

	if writeErr := os.WriteFile(docPath, body, 0640); writeErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write file: %s", writeErr.Error())})
		return
	}

	if _, uid, gid, uidErr := getLabDirectoryInfo(ownerUsername, c.Param("labName")); uidErr == nil {
		_ = os.Chown(targetDir, uid, gid)
		_ = os.Chown(docPath, uid, gid)
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// GetRunningLabYamlHandler returns the source YAML used by a running lab.
func GetRunningLabYamlHandler(c *gin.Context) {
	readRunningLabDoc(c, "yaml")
}

// PutRunningLabYamlHandler updates the source YAML used by a running lab.
func PutRunningLabYamlHandler(c *gin.Context) {
	writeRunningLabDoc(c, "yaml")
}

// GetRunningLabAnnotationsHandler returns the annotations JSON associated with a running lab.
func GetRunningLabAnnotationsHandler(c *gin.Context) {
	readRunningLabDoc(c, "annotations")
}

// PutRunningLabAnnotationsHandler updates or creates the annotations JSON associated with a running lab.
func PutRunningLabAnnotationsHandler(c *gin.Context) {
	writeRunningLabDoc(c, "annotations")
}
