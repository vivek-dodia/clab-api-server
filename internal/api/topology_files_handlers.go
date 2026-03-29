package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

type renameTopologyFileRequest struct {
	OldPath string `json:"oldPath" binding:"required"`
	NewPath string `json:"newPath" binding:"required"`
}

func resolveDefaultTopologyDocPath(username, labName, docType string) (string, string, int, int, error) {
	if !isValidLabName(labName) {
		return "", "", -1, -1, fmt.Errorf("invalid lab name")
	}

	fileName := labName + ".clab.yml"
	switch docType {
	case "yaml":
		// keep default
	case "annotations":
		fileName += ".annotations.json"
	default:
		return "", "", -1, -1, fmt.Errorf("invalid topology document type")
	}

	return resolveTopologyFilePath(username, labName, fileName)
}

func readDefaultTopologyDoc(c *gin.Context, docType string) {
	username := c.GetString("username")
	labName := c.Param("labName")

	absPath, _, _, _, err := resolveDefaultTopologyDocPath(username, labName, docType)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	content, readErr := os.ReadFile(absPath)
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

func writeDefaultTopologyDoc(c *gin.Context, docType string) {
	username := c.GetString("username")
	labName := c.Param("labName")

	absPath, labDir, uid, gid, err := resolveDefaultTopologyDocPath(username, labName, docType)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	body, readErr := io.ReadAll(c.Request.Body)
	if readErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Failed to read request body"})
		return
	}

	if mkdirErr := os.MkdirAll(labDir, 0750); mkdirErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure lab directory: %s", mkdirErr.Error())})
		return
	}
	_ = os.Chown(labDir, uid, gid)

	if writeErr := os.WriteFile(absPath, body, 0640); writeErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write file: %s", writeErr.Error())})
		return
	}
	_ = os.Chown(absPath, uid, gid)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ListTopologiesHandler returns editable topology files for the authenticated user.
func ListTopologiesHandler(c *gin.Context) {
	username := c.GetString("username")

	baseDir, err := getUserLabsBaseDirectory(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	deployedByLab := listDeployedLabsByName(username)
	entries, listErr := listTopologyEntries(baseDir, deployedByLab)
	if listErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: listErr.Error()})
		return
	}

	c.JSON(http.StatusOK, entries)
}

// DeployTopologyHandler deploys an on-disk topology identified by lab name.
func DeployTopologyHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	reconfigure := c.Query("reconfigure") == "true"
	maxWorkersStr := c.DefaultQuery("maxWorkers", "0")
	exportTemplate := c.Query("exportTemplate")
	nodeFilter := c.Query("nodeFilter")
	skipPostDeploy := c.Query("skipPostDeploy") == "true"
	skipLabdirAcl := c.Query("skipLabdirAcl") == "true"

	if !isValidNodeFilter(nodeFilter) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in 'nodeFilter' query parameter."})
		return
	}
	if !isValidExportTemplate(exportTemplate) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'exportTemplate' query parameter."})
		return
	}
	maxWorkers, err := strconv.Atoi(maxWorkersStr)
	if err != nil || maxWorkers < 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'maxWorkers' query parameter."})
		return
	}

	labDir, _, _, dirErr := getLabDirectoryInfo(username, labName)
	if dirErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: dirErr.Error()})
		return
	}

	topologyPath := filepath.Join(labDir, labName+".clab.yml")
	if _, statErr := os.Stat(topologyPath); statErr != nil {
		if os.IsNotExist(statErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Topology file not found for lab '%s'.", labName)})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to stat topology file: %s", statErr.Error())})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	labInfo, exists, checkErr := getLabInfo(ctx, username, labName)
	if checkErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Error checking lab '%s' status: %s", labName, checkErr.Error())})
		return
	}
	if exists {
		if !reconfigure {
			c.JSON(http.StatusConflict, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' already exists. Use 'reconfigure=true' to overwrite.", labName)})
			return
		}
		if !isSuperuser(username) && labInfo.Owner != username {
			c.JSON(http.StatusForbidden, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' is owned by '%s'. Permission denied.", labName, labInfo.Owner)})
			return
		}
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	var nodeFilterSlice []string
	if nodeFilter != "" {
		nodeFilterSlice = strings.Split(nodeFilter, ",")
	}

	deployCtx, deployCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer deployCancel()

	containers, deployErr := svc.Deploy(deployCtx, clab.DeployOptions{
		TopoPath:       topologyPath,
		Username:       username,
		Reconfigure:    reconfigure,
		MaxWorkers:     uint(maxWorkers),
		ExportTemplate: exportTemplate,
		NodeFilter:     nodeFilterSlice,
		SkipPostDeploy: skipPostDeploy,
		SkipLabDirACLs: skipLabdirAcl,
	})
	if deployErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to deploy lab '%s': %s", labName, deployErr.Error())})
		return
	}

	result := clab.ContainersToClabInspectOutput(containers)
	c.JSON(http.StatusOK, result)
}

// GetTopologyYamlHandler returns the canonical YAML topology file for the lab.
func GetTopologyYamlHandler(c *gin.Context) {
	readDefaultTopologyDoc(c, "yaml")
}

// PutTopologyYamlHandler writes the canonical YAML topology file for the lab.
func PutTopologyYamlHandler(c *gin.Context) {
	writeDefaultTopologyDoc(c, "yaml")
}

// GetTopologyAnnotationsHandler returns the canonical annotations document for the lab.
func GetTopologyAnnotationsHandler(c *gin.Context) {
	readDefaultTopologyDoc(c, "annotations")
}

// PutTopologyAnnotationsHandler writes the canonical annotations document for the lab.
func PutTopologyAnnotationsHandler(c *gin.Context) {
	writeDefaultTopologyDoc(c, "annotations")
}

func GetTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	relPath := c.Query("path")

	absPath, _, _, _, err := resolveTopologyFilePath(username, labName, relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	content, readErr := os.ReadFile(absPath)
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

func HeadTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	relPath := c.Query("path")

	absPath, _, _, _, err := resolveTopologyFilePath(username, labName, relPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	if _, statErr := os.Stat(absPath); statErr != nil {
		if os.IsNotExist(statErr) {
			c.Status(http.StatusNotFound)
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusOK)
}

func PutTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	relPath := c.Query("path")

	absPath, labDir, uid, gid, err := resolveTopologyFilePath(username, labName, relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	body, readErr := io.ReadAll(c.Request.Body)
	if readErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Failed to read request body"})
		return
	}

	if mkdirErr := os.MkdirAll(labDir, 0750); mkdirErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure lab directory: %s", mkdirErr.Error())})
		return
	}
	_ = os.Chown(labDir, uid, gid)

	if writeErr := os.WriteFile(absPath, body, 0640); writeErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write file: %s", writeErr.Error())})
		return
	}
	_ = os.Chown(absPath, uid, gid)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func DeleteTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	relPath := c.Query("path")

	absPath, _, _, _, err := resolveTopologyFilePath(username, labName, relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	if unlinkErr := os.Remove(absPath); unlinkErr != nil && !os.IsNotExist(unlinkErr) {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to delete file: %s", unlinkErr.Error())})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func RenameTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	var req renameTopologyFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	oldPath, _, _, _, oldErr := resolveTopologyFilePath(username, labName, req.OldPath)
	if oldErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: oldErr.Error()})
		return
	}

	newPath, _, _, _, newErr := resolveTopologyFilePath(username, labName, req.NewPath)
	if newErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: newErr.Error()})
		return
	}

	if mkdirErr := os.MkdirAll(filepath.Dir(newPath), 0750); mkdirErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure destination directory: %s", mkdirErr.Error())})
		return
	}

	if renameErr := os.Rename(oldPath, newPath); renameErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to rename file: %s", renameErr.Error())})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func listDeployedLabsByName(username string) map[string]bool {
	result := map[string]bool{}

	svc := GetClabService()
	if svc == nil {
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containers, err := svc.ListContainers(ctx, clab.ListOptions{})
	if err != nil {
		return result
	}

	superuser := isSuperuser(username)
	for _, container := range containers {
		info := clab.ContainerToClabContainerInfo(container)
		if superuser || info.Owner == username {
			result[info.LabName] = true
		}
	}

	return result
}

func listTopologyEntries(baseDir string, deployedByLab map[string]bool) ([]models.TopologyEntry, error) {
	entries := []models.TopologyEntry{}

	dirEntries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, fmt.Errorf("failed to read labs directory: %w", err)
	}

	for _, entry := range dirEntries {
		if !entry.IsDir() {
			continue
		}

		labName := entry.Name()
		if !isValidLabName(labName) {
			continue
		}

		labDir := filepath.Join(baseDir, labName)
		yamlFileName := labName + ".clab.yml"
		annotationsFileName := yamlFileName + ".annotations.json"
		yamlPath := filepath.Join(labDir, yamlFileName)
		annotationsPath := filepath.Join(labDir, annotationsFileName)

		if _, statErr := os.Stat(yamlPath); statErr != nil {
			continue
		}

		_, hasAnnotations := func() (os.FileInfo, bool) {
			info, err := os.Stat(annotationsPath)
			return info, err == nil
		}()

		deploymentState := "undeployed"
		if deployedByLab[labName] {
			deploymentState = "deployed"
		}

		entries = append(entries, models.TopologyEntry{
			LabName:             labName,
			YamlFileName:        yamlFileName,
			AnnotationsFileName: annotationsFileName,
			HasAnnotations:      hasAnnotations,
			DeploymentState:     deploymentState,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LabName < entries[j].LabName
	})

	return entries, nil
}

func getUserLabsBaseDirectory(username string) (string, error) {
	sentinelDir, _, _, err := getLabDirectoryInfo(username, "__sentinel__")
	if err != nil {
		return "", fmt.Errorf("failed to resolve labs directory: %w", err)
	}

	return filepath.Dir(sentinelDir), nil
}

func resolveTopologyFilePath(username, labName, relPath string) (absolutePath, labDir string, uid, gid int, err error) {
	if !isValidLabName(labName) {
		return "", "", -1, -1, fmt.Errorf("invalid lab name")
	}

	trimmed := strings.TrimSpace(relPath)
	if trimmed == "" {
		return "", "", -1, -1, fmt.Errorf("missing required query parameter 'path'")
	}

	cleanPath := filepath.Clean(trimmed)
	if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) || filepath.IsAbs(cleanPath) {
		return "", "", -1, -1, fmt.Errorf("invalid file path")
	}

	labDir, uid, gid, dirErr := getLabDirectoryInfo(username, labName)
	if dirErr != nil {
		return "", "", -1, -1, dirErr
	}

	absPath := filepath.Clean(filepath.Join(labDir, cleanPath))
	cleanLabDir := filepath.Clean(labDir)
	if absPath != cleanLabDir && !strings.HasPrefix(absPath, cleanLabDir+string(filepath.Separator)) {
		return "", "", -1, -1, fmt.Errorf("resolved path escapes lab directory")
	}

	return absPath, cleanLabDir, uid, gid, nil
}
