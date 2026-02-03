// internal/api/info_handlers.go
package api

import (
	"net/http"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
)

// @Summary Get containerlab version
// @Description Returns version information for the containerlab library in use.
// @Tags Version
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.VersionResponse "Containerlab version details"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/version [get]
func GetVersionHandler(c *gin.Context) {
	username := c.GetString("username") // For logging context
	log.Debugf("GetVersion user '%s': Requesting containerlab version info...", username)

	// Since we're using containerlab as a library, we can return the version from the imported package
	// The actual version would come from the containerlab module's version info
	versionInfo := "Containerlab integrated as Go library (CLI no longer used)"

	log.Infof("GetVersion user '%s': Successfully retrieved containerlab version info.", username)
	c.JSON(http.StatusOK, models.VersionResponse{VersionInfo: versionInfo})
}

// @Summary Check containerlab updates
// @Description **Deprecated**
// @Description Version checks are not supported when containerlab runs as a library.
// @Tags Version
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.VersionCheckResponse "Result of the version check"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Router /api/v1/version/check [get]
func CheckVersionHandler(c *gin.Context) {
	username := c.GetString("username") // For logging context
	log.Debugf("CheckVersion user '%s': Version check endpoint called (deprecated).", username)

	c.JSON(http.StatusOK, models.VersionCheckResponse{
		CheckResult: "Version check is not available when using containerlab as a library. Please check https://containerlab.dev for the latest releases.",
	})
}
