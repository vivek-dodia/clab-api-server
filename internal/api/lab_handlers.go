// internal/api/lab_handlers.go
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// @Summary Deploy lab
// @Description Deploys a containerlab topology.
// @Description
// @Description **Notes**
// @Description - The request body must include either `topologyContent` or `topologySourceUrl` (not both).
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param deploy_request body models.DeployRequest true "Deployment Source"
// @Param labNameOverride query string false "Override lab name when deploying from a URL (optional)"
// @Param reconfigure query boolean false "Allow overwriting an existing lab IF owned by the user"
// @Param maxWorkers query int false "Limit concurrent workers"
// @Param exportTemplate query string false "Custom Go template file for topology data export"
// @Param nodeFilter query string false "Comma-separated list of node names to deploy"
// @Param skipPostDeploy query boolean false "Skip post-deploy actions"
// @Param skipLabdirAcl query boolean false "Skip setting extended ACLs on lab directory"
// @Success 200 {object} models.ClabInspectOutput "Deployed lab details"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden"
// @Failure 409 {object} models.ErrorResponse "Conflict"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs [post]
func DeployLabHandler(c *gin.Context) {
	username := c.GetString("username")
	// Use a fresh context with timeout for long-running containerlab operations
	// The HTTP request context can be problematic for operations that take time
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// --- Bind Request Body ---
	var req models.DeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("DeployLab failed for user '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Validate Input ---
	hasContent := len(req.TopologyContent) > 0
	hasUrl := strings.TrimSpace(req.TopologySourceUrl) != ""

	if !hasContent && !hasUrl {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Request body must include either 'topologyContent' or 'topologySourceUrl'"})
		return
	}
	if hasContent && hasUrl {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Request body cannot include both 'topologyContent' and 'topologySourceUrl'"})
		return
	}

	// --- Get Query Parameters ---
	labNameOverride := c.Query("labNameOverride")
	reconfigure := c.Query("reconfigure") == "true"
	maxWorkersStr := c.DefaultQuery("maxWorkers", "0")
	exportTemplate := c.Query("exportTemplate")
	nodeFilter := c.Query("nodeFilter")
	skipPostDeploy := c.Query("skipPostDeploy") == "true"
	skipLabdirAcl := c.Query("skipLabdirAcl") == "true"

	// Validate query parameters
	if labNameOverride != "" && !isValidLabName(labNameOverride) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in 'labNameOverride' query parameter."})
		return
	}
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

	var effectiveLabName string
	var originalLabName string
	var topoPathForClab string
	var topoContent string

	if hasUrl {
		log.Infof("DeployLab user '%s': Deploying from URL: %s", username, req.TopologySourceUrl)
		_, urlErr := url.ParseRequestURI(req.TopologySourceUrl)
		isShortcut := !strings.Contains(req.TopologySourceUrl, "/") && !strings.Contains(req.TopologySourceUrl, ":")
		if urlErr != nil && !isShortcut && !strings.HasPrefix(req.TopologySourceUrl, "http") {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid topologySourceUrl format"})
			return
		}
		topoPathForClab = req.TopologySourceUrl

		if labNameOverride != "" {
			effectiveLabName = labNameOverride
		} else {
			effectiveLabName = "<determined_by_clab_from_url>"
		}
	} else {
		log.Infof("DeployLab user '%s': Deploying from provided topology content.", username)

		var topoData map[string]interface{}
		if err := json.Unmarshal(req.TopologyContent, &topoData); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid topology JSON: " + err.Error()})
			return
		}

		originalLabNameValue, ok := topoData["name"]
		if !ok {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "JSON topology must contain a top-level 'name' field."})
			return
		}
		originalLabName, ok = originalLabNameValue.(string)
		if !ok || originalLabName == "" {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Topology 'name' field must be a non-empty string."})
			return
		}
		if !isValidLabName(originalLabName) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in topology 'name'."})
			return
		}

		yamlBytes, err := yaml.Marshal(topoData)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Failed to convert JSON topology to YAML: " + err.Error()})
			return
		}
		topoContent = string(yamlBytes)

		if labNameOverride != "" {
			effectiveLabName = labNameOverride
		} else {
			effectiveLabName = originalLabName
		}
	}

	// --- Pre-Deployment Check ---
	if effectiveLabName != "<determined_by_clab_from_url>" {
		labInfo, exists, checkErr := getLabInfo(ctx, username, effectiveLabName)
		if checkErr != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Error checking lab '%s' status: %s", effectiveLabName, checkErr.Error())})
			return
		}

		if exists {
			if !reconfigure {
				c.JSON(http.StatusConflict, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' already exists. Use 'reconfigure=true' to overwrite.", effectiveLabName)})
				return
			}
			if !isSuperuser(username) && labInfo.Owner != username {
				c.JSON(http.StatusForbidden, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' is owned by '%s'. Permission denied.", effectiveLabName, labInfo.Owner)})
				return
			}
			log.Infof("DeployLab user '%s': Lab '%s' exists, reconfigure=true, proceeding.", username, effectiveLabName)
		}
	}

	// --- Save Topology Content (if applicable) ---
	if hasContent {
		targetDir, uid, gid, err := getLabDirectoryInfo(username, originalLabName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
			return
		}

		targetFilePath := filepath.Join(targetDir, originalLabName+".clab.yml")
		topoPathForClab = targetFilePath

		if err := os.MkdirAll(targetDir, 0750); err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create lab directory: %s", err.Error())})
			return
		}
		_ = os.Chown(targetDir, uid, gid)

		if err := os.WriteFile(targetFilePath, []byte(strings.TrimSpace(topoContent)), 0640); err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write topology file: %s", err.Error())})
			return
		}
		if err := os.Chown(targetFilePath, uid, gid); err != nil {
			_ = os.Remove(targetFilePath)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to set ownership on topology file: %s", err.Error())})
			return
		}
		log.Infof("Saved topology for user '%s' lab '%s' to '%s'", username, originalLabName, targetFilePath)
	}

	// --- Deploy using library ---
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	var nodeFilterSlice []string
	if nodeFilter != "" {
		nodeFilterSlice = strings.Split(nodeFilter, ",")
	}

	deployOpts := clab.DeployOptions{
		TopoPath:       topoPathForClab,
		Username:       username,
		Reconfigure:    reconfigure,
		MaxWorkers:     uint(maxWorkers),
		ExportTemplate: exportTemplate,
		NodeFilter:     nodeFilterSlice,
		SkipPostDeploy: skipPostDeploy,
		SkipLabDirACLs: skipLabdirAcl,
	}

	log.Infof("DeployLab user '%s': Deploying lab '%s'...", username, effectiveLabName)
	containers, err := svc.Deploy(ctx, deployOpts)
	if err != nil {
		log.Errorf("DeployLab failed for user '%s', lab '%s': %v", username, effectiveLabName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to deploy lab '%s': %s", effectiveLabName, err.Error())})
		return
	}

	log.Infof("DeployLab user '%s': Lab '%s' deployed successfully.", username, effectiveLabName)

	// Convert containers to response format
	result := clab.ContainersToClabInspectOutput(containers)
	c.JSON(http.StatusOK, result)
}

// @Summary Deploy lab from archive
// @Description Deploys a containerlab topology provided as a .zip or .tar.gz archive.
// @Tags Labs
// @Security BearerAuth
// @Accept multipart/form-data
// @Produce json
// @Param labArchive formData file true "Lab archive (.zip or .tar.gz)"
// @Param labName query string true "Name for the lab"
// @Param reconfigure query boolean false "Allow overwriting an existing lab"
// @Param maxWorkers query int false "Limit concurrent workers"
// @Param exportTemplate query string false "Custom Go template file for topology data export"
// @Param nodeFilter query string false "Comma-separated list of node names to deploy"
// @Param skipPostDeploy query boolean false "Skip post-deploy actions"
// @Param skipLabdirAcl query boolean false "Skip setting extended ACLs on lab directory"
// @Success 200 {object} models.ClabInspectOutput "Deployed lab details"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden"
// @Failure 409 {object} models.ErrorResponse "Conflict"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/archive [post]
func DeployLabArchiveHandler(c *gin.Context) {
	username := c.GetString("username")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	labName := c.Query("labName")
	if labName == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Missing required 'labName' query parameter."})
		return
	}
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in 'labName' query parameter."})
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

	// Pre-check for existing lab
	labInfo, exists, checkErr := getLabInfo(ctx, username, labName)
	if checkErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Error checking lab '%s' status: %s", labName, checkErr.Error())})
		return
	}

	targetDir, uid, gid, err := getLabDirectoryInfo(username, labName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
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
		if err := os.RemoveAll(targetDir); err != nil {
			log.Warnf("DeployLab (Archive) user '%s': Failed to remove existing directory: %v", username, err)
		}
	}

	if err := os.MkdirAll(targetDir, 0750); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to create lab directory."})
		return
	}
	_ = os.Chown(targetDir, uid, gid)

	fileHeader, err := c.FormFile("labArchive")
	if err != nil {
		_ = os.RemoveAll(targetDir)
		if err == http.ErrMissingFile {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Missing 'labArchive' file in multipart form data."})
		} else {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Error retrieving 'labArchive' file: " + err.Error()})
		}
		return
	}

	archiveFile, err := fileHeader.Open()
	if err != nil {
		_ = os.RemoveAll(targetDir)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Cannot open uploaded archive."})
		return
	}
	defer archiveFile.Close()

	filename := fileHeader.Filename
	var extractionErr error

	if strings.HasSuffix(strings.ToLower(filename), ".zip") {
		extractionErr = extractZip(archiveFile, fileHeader.Size, targetDir, uid, gid)
	} else if strings.HasSuffix(strings.ToLower(filename), ".tar.gz") || strings.HasSuffix(strings.ToLower(filename), ".tgz") {
		extractionErr = extractTarGz(archiveFile, targetDir, uid, gid)
	} else {
		_ = os.RemoveAll(targetDir)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Unsupported archive format: %s. Use .zip or .tar.gz.", filename)})
		return
	}

	if extractionErr != nil {
		_ = os.RemoveAll(targetDir)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to extract archive: %s", extractionErr.Error())})
		return
	}

	// Find topology file
	topoPathForClab := ""
	expectedTopoPath := filepath.Join(targetDir, labName+".clab.yml")
	if _, err := os.Stat(expectedTopoPath); err == nil {
		topoPathForClab = expectedTopoPath
	} else {
		entries, readErr := os.ReadDir(targetDir)
		if readErr != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to read extracted lab directory."})
			_ = os.RemoveAll(targetDir)
			return
		}
		for _, entry := range entries {
			entryNameLower := strings.ToLower(entry.Name())
			if !entry.IsDir() && (strings.HasSuffix(entryNameLower, ".clab.yml") || strings.HasSuffix(entryNameLower, ".clab.yaml")) {
				topoPathForClab = filepath.Join(targetDir, entry.Name())
				break
			}
		}
	}

	if topoPathForClab == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "No '*.clab.yml' or '*.clab.yaml' file found in the archive."})
		_ = os.RemoveAll(targetDir)
		return
	}

	// Deploy using library
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	var nodeFilterSlice []string
	if nodeFilter != "" {
		nodeFilterSlice = strings.Split(nodeFilter, ",")
	}

	deployOpts := clab.DeployOptions{
		TopoPath:       topoPathForClab,
		Username:       username,
		Reconfigure:    reconfigure,
		MaxWorkers:     uint(maxWorkers),
		ExportTemplate: exportTemplate,
		NodeFilter:     nodeFilterSlice,
		SkipPostDeploy: skipPostDeploy,
		SkipLabDirACLs: skipLabdirAcl,
	}

	log.Infof("DeployLab (Archive) user '%s': Deploying lab '%s'...", username, labName)
	containers, err := svc.Deploy(ctx, deployOpts)
	if err != nil {
		log.Errorf("DeployLab (Archive) failed for user '%s', lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to deploy lab '%s': %s", labName, err.Error())})
		return
	}

	log.Infof("DeployLab (Archive) user '%s': Lab '%s' deployed successfully.", username, labName)
	result := clab.ContainersToClabInspectOutput(containers)
	c.JSON(http.StatusOK, result)
}

// @Summary Destroy lab
// @Description Destroys a lab by name after verifying ownership.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to destroy"
// @Param cleanup query boolean false "Remove containerlab lab artifacts after destroy"
// @Param purgeLabDir query boolean false "Purge topology parent directory for managed lab paths (~/.clab or shared labs dir)"
// @Param graceful query boolean false "Attempt graceful shutdown"
// @Param keepMgmtNet query boolean false "Keep the management network"
// @Param nodeFilter query string false "Destroy only specific nodes"
// @Success 200 {object} models.GenericSuccessResponse "Lab destroyed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName} [delete]
func DestroyLabHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	cleanup := c.Query("cleanup") == "true"
	purgeLabDir := c.Query("purgeLabDir") == "true"
	graceful := c.Query("graceful") == "true"
	keepMgmtNet := c.Query("keepMgmtNet") == "true"
	nodeFilter := c.Query("nodeFilter")

	if !isValidNodeFilter(nodeFilter) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in nodeFilter."})
		return
	}

	originalTopoPath, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return
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

	destroyOpts := clab.DestroyOptions{
		LabName:     labName,
		TopoPath:    originalTopoPath,
		Username:    username,
		Graceful:    graceful,
		Cleanup:     cleanup, // Keep containerlab cleanup behavior for all topology locations.
		KeepMgmtNet: keepMgmtNet,
		NodeFilter:  nodeFilterSlice,
	}

	log.Infof("DestroyLab user '%s': Destroying lab '%s' (cleanup=%t, purgeLabDir=%t)...", username, labName, cleanup, purgeLabDir)
	if err := svc.Destroy(ctx, destroyOpts); err != nil {
		log.Errorf("DestroyLab failed for user '%s', lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to destroy lab '%s': %s", labName, err.Error())})
		return
	}

	log.Infof("Lab '%s' destroyed successfully for user '%s'.", labName, username)

	// Purge topology parent directory if requested.
	if purgeLabDir && originalTopoPath != "" && !strings.HasPrefix(originalTopoPath, "http") {
		targetDir := filepath.Dir(originalTopoPath)

		sharedDir := os.Getenv("CLAB_SHARED_LABS_DIR")
		expectedBase := ""
		if sharedDir != "" {
			expectedBase = filepath.Join(sharedDir, "users", username)
		} else {
			usr, lookupErr := user.Lookup(username)
			if lookupErr == nil {
				expectedBase = filepath.Join(usr.HomeDir, ".clab")
			}
		}

		if expectedBase != "" && strings.HasPrefix(targetDir, expectedBase) && targetDir != expectedBase {
			if err := os.RemoveAll(targetDir); err != nil {
				log.Warnf("Failed to cleanup directory '%s' for user '%s': %v", targetDir, username, err)
			} else {
				log.Infof("Successfully cleaned up directory '%s' for user '%s'", targetDir, username)
			}
		}
	}

	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: fmt.Sprintf("Lab '%s' destroyed successfully", labName)})
}

// @Summary Redeploy lab
// @Description Redeploys a lab by name.
// @Description
// @Description **Notes**
// @Description - This operation destroys the lab and then deploys it again.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to redeploy"
// @Param cleanup query boolean false "Remove containerlab lab artifacts during destroy phase"
// @Param graceful query boolean false "Attempt graceful shutdown"
// @Param keepMgmtNet query boolean false "Keep the management network"
// @Param maxWorkers query int false "Limit concurrent workers"
// @Param exportTemplate query string false "Custom Go template file for topology data export"
// @Param skipPostDeploy query boolean false "Skip post-deploy actions"
// @Param skipLabdirAcl query boolean false "Skip setting extended ACLs on lab directory"
// @Success 200 {object} models.ClabInspectOutput "Redeployed lab details"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName} [put]
func RedeployLabHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	cleanup := c.Query("cleanup") == "true"
	graceful := c.Query("graceful") == "true"
	keepMgmtNet := c.Query("keepMgmtNet") == "true"
	maxWorkersStr := c.DefaultQuery("maxWorkers", "0")
	skipPostDeploy := c.Query("skipPostDeploy") == "true"
	exportTemplate := c.Query("exportTemplate")
	skipLabdirAcl := c.Query("skipLabdirAcl") == "true"

	if !isValidExportTemplate(exportTemplate) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'exportTemplate' query parameter."})
		return
	}
	maxWorkers, err := strconv.Atoi(maxWorkersStr)
	if err != nil || maxWorkers < 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'maxWorkers' query parameter."})
		return
	}

	originalTopoPath, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return
	}
	if originalTopoPath == "" {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not determine original topology path for redeploy."})
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get current owner
	targetOwner := username
	if info, exists, err := getLabInfo(ctx, username, labName); err == nil && exists && info != nil && info.Owner != "" {
		targetOwner = info.Owner
	}

	// Destroy
	destroyOpts := clab.DestroyOptions{
		TopoPath:    originalTopoPath,
		Username:    username,
		Graceful:    graceful,
		Cleanup:     cleanup,
		KeepMgmtNet: keepMgmtNet,
		MaxWorkers:  uint(maxWorkers),
	}

	log.Infof("RedeployLab user '%s': Destroying lab '%s'...", username, labName)
	if err := svc.Destroy(ctx, destroyOpts); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to destroy lab '%s': %s", labName, err.Error())})
		return
	}

	// Deploy
	deployOpts := clab.DeployOptions{
		TopoPath:       originalTopoPath,
		Username:       targetOwner,
		Reconfigure:    true,
		MaxWorkers:     uint(maxWorkers),
		ExportTemplate: exportTemplate,
		SkipPostDeploy: skipPostDeploy,
		SkipLabDirACLs: skipLabdirAcl,
	}

	log.Infof("RedeployLab user '%s': Deploying lab '%s'...", username, labName)
	containers, err := svc.Deploy(ctx, deployOpts)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to redeploy lab '%s': %s", labName, err.Error())})
		return
	}

	log.Infof("RedeployLab user '%s': Lab '%s' redeployed successfully.", username, labName)
	result := clab.ContainersToClabInspectOutput(containers)
	c.JSON(http.StatusOK, result)
}

// @Summary Inspect lab
// @Description Returns details for a specific running lab.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to inspect"
// @Success 200 {object} []models.ClabContainerInfo "Lab containers"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName} [get]
func InspectLabHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	_, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containers, err := svc.ListContainers(ctx, clab.ListOptions{LabName: labName})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect lab '%s': %s", labName, err.Error())})
		return
	}

	var labContainers []models.ClabContainerInfo
	for _, cont := range containers {
		containerInfo := clab.ContainerToClabContainerInfo(cont)
		if containerInfo.LabName == labName {
			labContainers = append(labContainers, containerInfo)
		}
	}

	if len(labContainers) == 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found.", labName)})
		return
	}

	log.Debugf("InspectLab user '%s': Inspection of lab '%s' successful.", username, labName)
	c.JSON(http.StatusOK, labContainers)
}

// @Summary List lab interfaces
// @Description Returns interface details for nodes in a lab.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab"
// @Param node query string false "Filter interfaces for a specific node"
// @Success 200 {object} models.ClabInspectInterfacesOutput "Interface details"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/interfaces [get]
func InspectInterfacesHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeFilter := c.Query("node")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}
	if nodeFilter != "" && !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(nodeFilter) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in node query parameter."})
		return
	}

	_, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containers, err := svc.ListContainers(ctx, clab.ListOptions{LabName: labName})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to list containers for lab '%s': %s", labName, err.Error())})
		return
	}

	if len(containers) == 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found.", labName)})
		return
	}

	// Get interfaces for each container
	interfaces, err := svc.ListContainersInterfaces(ctx, containers)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to get interfaces for lab '%s': %s", labName, err.Error())})
		return
	}

	result := clab.ContainersInterfacesToInspectOutput(interfaces)

	// Filter by node if requested
	if nodeFilter != "" {
		var filtered models.ClabInspectInterfacesOutput
		for _, ni := range result {
			if strings.Contains(ni.NodeName, nodeFilter) {
				filtered = append(filtered, ni)
			}
		}
		result = filtered
	}

	log.Debugf("InspectInterfaces user '%s': Inspection of interfaces for lab '%s' successful.", username, labName)
	c.JSON(http.StatusOK, result)
}

// @Summary List labs
// @Description Returns details for all running labs.
// @Description
// @Description **Notes**
// @Description - Results are filtered by owner unless the caller is a superuser.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.ClabInspectOutput "All labs"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs [get]
func ListLabsHandler(c *gin.Context) {
	username := c.GetString("username")
	isSuperuserUser := isSuperuser(username)

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containers, err := svc.ListContainers(ctx, clab.ListOptions{})
	if err != nil {
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "no containers found") || strings.Contains(errMsg, "no containerlab labs found") {
			c.JSON(http.StatusOK, models.ClabInspectOutput{})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to list labs: %s", err.Error())})
		return
	}

	// Group by lab and filter by owner
	fullResult := clab.ContainersToClabInspectOutput(containers)

	if isSuperuserUser {
		log.Debugf("ListLabs user '%s': Superuser returning all %d labs.", username, len(fullResult))
		c.JSON(http.StatusOK, fullResult)
		return
	}

	// Filter by owner
	finalResult := make(models.ClabInspectOutput)
	for labName, labContainers := range fullResult {
		for _, cont := range labContainers {
			if cont.Owner == username {
				finalResult[labName] = labContainers
				break
			}
		}
	}

	log.Infof("ListLabs user '%s': Found %d labs owned by the user.", username, len(finalResult))
	c.JSON(http.StatusOK, finalResult)
}

// @Summary Save lab configuration
// @Description Saves the running configuration for nodes in a lab.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab"
// @Param nodeFilter query string false "Save config only for specific nodes"
// @Success 200 {object} models.SaveConfigResponse "Configuration saved"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/save [post]
func SaveLabConfigHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeFilter := c.Query("nodeFilter")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}
	if !isValidNodeFilter(nodeFilter) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in nodeFilter."})
		return
	}

	originalTopoPath, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return
	}
	if originalTopoPath == "" {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not determine topology path for save."})
		return
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

	saveOpts := clab.SaveOptions{
		TopoPath:   originalTopoPath,
		Username:   username,
		NodeFilter: nodeFilterSlice,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Infof("SaveLabConfig user '%s': Saving config for lab '%s'...", username, labName)
	if err := svc.SaveConfig(ctx, saveOpts); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to save config for lab '%s': %s", labName, err.Error())})
		return
	}

	log.Infof("SaveLabConfig user '%s': Config saved successfully for lab '%s'.", username, labName)
	c.JSON(http.StatusOK, models.SaveConfigResponse{
		Message: fmt.Sprintf("Configuration save command executed successfully for lab '%s'.", labName),
		Output:  "Configuration saved via library",
	})
}

// @Summary Execute command in lab
// @Description Executes a command on nodes within a lab.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Name of the lab"
// @Param nodeFilter query string false "Execute only on this specific node"
// @Param exec_request body models.ExecRequest true "Command to execute"
// @Success 200 {object} models.ExecResponse "Execution result"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/exec [post]
func ExecCommandHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeFilter := c.Query("nodeFilter")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}
	if nodeFilter != "" && !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(nodeFilter) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in nodeFilter."})
		return
	}
	var req models.ExecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Command cannot be empty."})
		return
	}

	originalTopoPath, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	execOpts := clab.ExecOptions{
		TopoPath:      originalTopoPath,
		LabName:       labName,
		ContainerName: nodeFilter,
		Commands:      []string{req.Command},
		Username:      username,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Infof("ExecCommand user '%s': Executing command on lab '%s'...", username, labName)
	result, err := svc.Exec(ctx, execOpts)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to execute command on lab '%s': %s", labName, err.Error())})
		return
	}

	// Convert result to API format
	response := clab.ExecCollectionToExecResponse(result)

	log.Infof("ExecCommand user '%s': Command executed successfully on lab '%s'.", username, labName)
	c.JSON(http.StatusOK, response)
}
