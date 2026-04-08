package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/models"
)

var interfaceNameRx = regexp.MustCompile(`^[a-zA-Z0-9._:/-]+$`)

func getCaptureManager(c *gin.Context) *capture.Manager {
	manager := GetCaptureManager()
	if manager == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Capture service is not initialized"})
		return nil
	}
	return manager
}

func mapCaptureSessionError(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, capture.ErrSessionNotFound):
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
	case errors.Is(err, capture.ErrSessionForbidden):
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: err.Error()})
	default:
		return false
	}
	return true
}

func mapCaptureOperationError(c *gin.Context, err error) {
	if errors.Is(err, capture.ErrEdgeSharkNotRunning) {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse{
			Error: "Edgeshark is not running. Start it from settings before launching capture.",
		})
		return
	}
	c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
}

func resolveLabDirectory(containerInfo *models.ClabContainerInfo) string {
	if containerInfo == nil {
		return ""
	}
	if abs := strings.TrimSpace(containerInfo.AbsLabPath); abs != "" {
		return filepath.Dir(abs)
	}
	if labPath := strings.TrimSpace(containerInfo.LabPath); labPath != "" && filepath.IsAbs(labPath) {
		return filepath.Dir(labPath)
	}
	return ""
}

func buildCaptureSpecs(
	c *gin.Context,
	username string,
	labName string,
	targets []models.CaptureTarget,
) ([]capture.ContainerCaptureSpec, bool) {
	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "At least one capture target is required"})
		return nil, false
	}

	specs := make([]capture.ContainerCaptureSpec, 0, len(targets))
	indexByContainer := make(map[string]int, len(targets))
	seenInterfacesByContainer := make(map[string]map[string]struct{}, len(targets))

	for _, target := range targets {
		containerName := strings.TrimSpace(target.ContainerName)
		ifaceName := strings.TrimSpace(target.InterfaceName)

		if !isValidContainerName(containerName) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Error: fmt.Sprintf("Invalid container name format: %q", containerName),
			})
			return nil, false
		}
		if ifaceName == "" || !interfaceNameRx.MatchString(ifaceName) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Error: fmt.Sprintf("Invalid interface name format: %q", ifaceName),
			})
			return nil, false
		}

		specIdx, exists := indexByContainer[containerName]
		if !exists {
			containerInfo, err := verifyContainerOwnership(c, username, containerName)
			if err != nil {
				return nil, false
			}
			if containerInfo.LabName != labName {
				c.JSON(http.StatusBadRequest, models.ErrorResponse{
					Error: fmt.Sprintf("Container '%s' does not belong to lab '%s'", containerName, labName),
				})
				return nil, false
			}

			specs = append(specs, capture.ContainerCaptureSpec{
				ContainerName:  containerName,
				InterfaceNames: []string{},
				LabDirectory:   resolveLabDirectory(containerInfo),
			})
			specIdx = len(specs) - 1
			indexByContainer[containerName] = specIdx
			seenInterfacesByContainer[containerName] = map[string]struct{}{}
		}

		if _, duplicate := seenInterfacesByContainer[containerName][ifaceName]; duplicate {
			continue
		}
		seenInterfacesByContainer[containerName][ifaceName] = struct{}{}
		specs[specIdx].InterfaceNames = append(specs[specIdx].InterfaceNames, ifaceName)
	}

	filtered := make([]capture.ContainerCaptureSpec, 0, len(specs))
	for _, spec := range specs {
		if len(spec.InterfaceNames) > 0 {
			filtered = append(filtered, spec)
		}
	}
	if len(filtered) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "No valid capture interfaces were provided"})
		return nil, false
	}
	return filtered, true
}

// GetEdgeSharkStatusHandler returns current edgeshark availability.
// @Summary Get EdgeShark status
// @Description Returns whether EdgeShark is reachable and its runtime details.
// @Tags Capture
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.EdgeSharkStatusResponse "EdgeShark status"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/tools/edgeshark/status [get]
func GetEdgeSharkStatusHandler(c *gin.Context) {
	manager := getCaptureManager(c)
	if manager == nil {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
	defer cancel()

	status, err := manager.Status(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.EdgeSharkStatusResponse{
		Running:        status.Running,
		Version:        status.Version,
		PacketflixPort: manager.PacketflixPort(),
		Runtime:        manager.Runtime(),
	})
}

// InstallEdgeSharkHandler installs edgeshark using compose.
// @Summary Install EdgeShark
// @Description Installs and starts EdgeShark services on the host runtime using compose.
// @Tags Capture
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.GenericSuccessResponse "EdgeShark installed"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Superuser privileges required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/tools/edgeshark/install [post]
func InstallEdgeSharkHandler(c *gin.Context) {
	username := c.GetString("username")
	if !requireSuperuser(c, username, "install edgeshark") {
		return
	}

	manager := getCaptureManager(c)
	if manager == nil {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()

	if err := manager.InstallEdgeShark(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: "Edgeshark installed"})
}

// UninstallEdgeSharkHandler removes edgeshark compose services.
// @Summary Uninstall EdgeShark
// @Description Stops and removes EdgeShark services managed by compose.
// @Tags Capture
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.GenericSuccessResponse "EdgeShark uninstalled"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Superuser privileges required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/tools/edgeshark/uninstall [post]
func UninstallEdgeSharkHandler(c *gin.Context) {
	username := c.GetString("username")
	if !requireSuperuser(c, username, "uninstall edgeshark") {
		return
	}

	manager := getCaptureManager(c)
	if manager == nil {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()

	if err := manager.UninstallEdgeShark(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: "Edgeshark uninstalled"})
}

// BuildPacketflixCaptureHandler generates packetflix URIs for capture targets.
// @Summary Build packetflix capture URI
// @Description Builds packetflix URI(s) for the provided lab interface targets (non-VNC capture mode).
// @Tags Capture
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab name" example="my-lab"
// @Param capture_request body models.CapturePacketflixRequest true "Packetflix capture request"
// @Success 200 {object} models.CapturePacketflixResponse "Packetflix capture URI payload"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden"
// @Failure 404 {object} models.ErrorResponse "Lab or container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Failure 503 {object} models.ErrorResponse "EdgeShark not running"
// @Router /api/v1/labs/{labName}/capture/packetflix [post]
func BuildPacketflixCaptureHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}

	if _, err := verifyLabOwnership(c, username, labName); err != nil {
		return
	}

	manager := getCaptureManager(c)
	if manager == nil {
		return
	}

	var req models.CapturePacketflixRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	specs, ok := buildCaptureSpecs(c, username, labName, req.Targets)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	captures, err := manager.BuildPacketflixURIs(ctx, specs, req.RemoteHostname)
	if err != nil {
		mapCaptureOperationError(c, err)
		return
	}

	response := models.CapturePacketflixResponse{Captures: make([]models.CapturePacketflixURI, 0, len(captures))}
	for _, captureURI := range captures {
		response.Captures = append(response.Captures, models.CapturePacketflixURI{
			ContainerName:  captureURI.ContainerName,
			InterfaceNames: captureURI.InterfaceNames,
			PacketflixURI:  captureURI.URI,
		})
	}

	c.JSON(http.StatusOK, response)
}

// CreateWiresharkVncSessionsHandler launches wireshark noVNC sessions for capture targets.
// @Summary Create Wireshark VNC capture session(s)
// @Description Creates one or more Wireshark noVNC capture sessions for the specified lab interface targets.
// @Tags Capture
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab name" example="my-lab"
// @Param capture_request body models.CaptureWiresharkVncRequest true "Wireshark VNC capture request"
// @Success 200 {object} models.CaptureWiresharkVncCreateResponse "Created capture sessions"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden"
// @Failure 404 {object} models.ErrorResponse "Lab or container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Failure 503 {object} models.ErrorResponse "EdgeShark not running"
// @Router /api/v1/labs/{labName}/capture/wireshark-vnc-sessions [post]
func CreateWiresharkVncSessionsHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	if _, err := verifyLabOwnership(c, username, labName); err != nil {
		return
	}

	manager := getCaptureManager(c)
	if manager == nil {
		return
	}

	var req models.CaptureWiresharkVncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	specs, ok := buildCaptureSpecs(c, username, labName, req.Targets)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()

	sessions, err := manager.CreateWiresharkSessions(ctx, capture.CreateWiresharkSessionsOptions{
		Username: username,
		LabName:  labName,
		Theme:    req.Theme,
		Specs:    specs,
	})
	if err != nil {
		mapCaptureOperationError(c, err)
		return
	}

	response := models.CaptureWiresharkVncCreateResponse{
		Sessions: make([]models.CaptureWiresharkVncSession, 0, len(sessions)),
	}
	for _, session := range sessions {
		response.Sessions = append(response.Sessions, models.CaptureWiresharkVncSession{
			SessionID:      session.SessionID,
			LabName:        session.LabName,
			ContainerName:  session.ContainerName,
			InterfaceNames: session.InterfaceNames,
			VncPath:        session.VncPath,
			ShowVolumeTip:  session.ShowVolumeTip,
			CreatedAt:      session.CreatedAt,
			ExpiresAt:      session.ExpiresAt,
		})
	}

	c.JSON(http.StatusOK, response)
}

// GetWiresharkVncSessionReadyHandler checks if a wireshark VNC session is reachable.
// @Summary Get Wireshark VNC session readiness
// @Description Returns whether a capture VNC session is ready and its proxied URL path.
// @Tags Capture
// @Security BearerAuth
// @Produce json
// @Param sessionId path string true "Capture session ID"
// @Success 200 {object} models.CaptureWiresharkVncReadyResponse "Readiness state"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden"
// @Failure 404 {object} models.ErrorResponse "Session not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/capture/wireshark-vnc-sessions/{sessionId}/ready [get]
func GetWiresharkVncSessionReadyHandler(c *gin.Context) {
	username := c.GetString("username")
	sessionID := strings.TrimSpace(c.Param("sessionId"))
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Missing session id"})
		return
	}

	manager := getCaptureManager(c)
	if manager == nil {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
	defer cancel()

	ready, urlPath, err := manager.SessionReady(ctx, sessionID, username, isSuperuser(username))
	if err != nil {
		if mapCaptureSessionError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.CaptureWiresharkVncReadyResponse{
		Ready: ready,
		URL:   urlPath,
	})
}

// DeleteWiresharkVncSessionHandler terminates a running wireshark VNC session.
// @Summary Delete Wireshark VNC session
// @Description Terminates a capture VNC session and stops the corresponding Wireshark container.
// @Tags Capture
// @Security BearerAuth
// @Produce json
// @Param sessionId path string true "Capture session ID"
// @Success 200 {object} models.GenericSuccessResponse "Capture session terminated"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden"
// @Failure 404 {object} models.ErrorResponse "Session not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/capture/wireshark-vnc-sessions/{sessionId} [delete]
func DeleteWiresharkVncSessionHandler(c *gin.Context) {
	username := c.GetString("username")
	sessionID := strings.TrimSpace(c.Param("sessionId"))
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Missing session id"})
		return
	}

	manager := getCaptureManager(c)
	if manager == nil {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	if err := manager.CloseSession(ctx, sessionID, username, isSuperuser(username)); err != nil {
		if mapCaptureSessionError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: "Capture session terminated"})
}

// DeleteAllWiresharkVncSessionsHandler terminates all running wireshark VNC sessions
// owned by the current user (or all sessions for a superuser).
// @Summary Delete all Wireshark VNC sessions
// @Description Terminates all capture VNC sessions owned by the authenticated user. Superusers terminate all sessions.
// @Tags Capture
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.CaptureCloseAllResponse "Capture sessions terminated"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/capture/wireshark-vnc-sessions [delete]
func DeleteAllWiresharkVncSessionsHandler(c *gin.Context) {
	username := c.GetString("username")

	manager := getCaptureManager(c)
	if manager == nil {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	closed, err := manager.CloseAllSessions(ctx, username, isSuperuser(username))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.CaptureCloseAllResponse{
		Message: fmt.Sprintf("Closed %d capture session(s)", closed),
		Closed:  closed,
	})
}

// ProxyWiresharkVncSessionHandler proxies noVNC assets and websocket traffic.
// @Summary Proxy Wireshark VNC assets
// @Description Proxies noVNC HTTP assets for a capture session. WebSocket upgrades on this path are used by noVNC but are not represented in Swagger.
// @Tags Capture
// @Security BearerAuth
// @Produce html
// @Param sessionId path string true "Capture session ID"
// @Param proxyPath path string true "Proxy subpath under the noVNC root"
// @Success 200 {string} string "Proxied noVNC asset response"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden"
// @Failure 404 {object} models.ErrorResponse "Session not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Failure 502 {object} models.ErrorResponse "VNC proxy upstream error"
// @Router /api/v1/capture/wireshark-vnc-sessions/{sessionId}/vnc/{proxyPath} [get]
func ProxyWiresharkVncSessionHandler(c *gin.Context) {
	username := c.GetString("username")
	sessionID := strings.TrimSpace(c.Param("sessionId"))
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Missing session id"})
		return
	}

	manager := getCaptureManager(c)
	if manager == nil {
		return
	}

	targetBaseURL, err := manager.ResolveProxyTarget(sessionID, username, isSuperuser(username))
	if err != nil {
		if mapCaptureSessionError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	targetURL, err := url.Parse(targetBaseURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to resolve proxy target"})
		return
	}

	proxyPath := c.Param("proxyPath")
	if proxyPath == "" {
		proxyPath = "/"
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	originalDirector := proxy.Director
	rawQuery := c.Request.URL.RawQuery
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = joinProxyPath(targetURL.Path, proxyPath)
		req.URL.RawPath = req.URL.EscapedPath()
		req.URL.RawQuery = rawQuery
		req.Host = targetURL.Host
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = writer.Write([]byte(fmt.Sprintf(`{"error":"VNC proxy error: %s"}`, proxyErr.Error())))
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

func joinProxyPath(base, tail string) string {
	baseSlash := strings.HasSuffix(base, "/")
	tailSlash := strings.HasPrefix(tail, "/")
	switch {
	case baseSlash && tailSlash:
		return base + tail[1:]
	case !baseSlash && !tailSlash:
		return base + "/" + tail
	default:
		return base + tail
	}
}
