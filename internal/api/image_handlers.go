package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

func toRuntimeImageSummary(image clab.RuntimeImageSummary) models.RuntimeImageSummary {
	return models.RuntimeImageSummary{
		ID:          image.ID,
		ShortID:     image.ShortID,
		RepoTags:    image.RepoTags,
		RepoDigests: image.RepoDigests,
		CreatedAt:   image.CreatedAt,
		Size:        image.Size,
		VirtualSize: image.VirtualSize,
	}
}

// @Summary List runtime images
// @Tags Images
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.RuntimeImagesResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/images [get]
func ListRuntimeImagesHandler(c *gin.Context) {
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	images, err := svc.ListRuntimeImages(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	responseImages := make([]models.RuntimeImageSummary, 0, len(images))
	for _, image := range images {
		responseImages = append(responseImages, toRuntimeImageSummary(image))
	}

	runtimeName := strings.TrimSpace(config.AppConfig.ClabRuntime)
	if runtimeName == "" {
		runtimeName = "docker"
	}

	c.JSON(http.StatusOK, models.RuntimeImagesResponse{
		Runtime: runtimeName,
		Images:  responseImages,
	})
}

// @Summary Pull a runtime image
// @Tags Images
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.RuntimeImagePullRequest true "Image reference"
// @Success 200 {object} models.RuntimeImageActionResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/images/pull [post]
func PullRuntimeImageHandler(c *gin.Context) {
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	var req models.RuntimeImagePullRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}
	image := strings.TrimSpace(req.Image)
	if !isValidRuntimeImageReference(image) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid image reference"})
		return
	}

	output, err := svc.PullRuntimeImage(c.Request.Context(), image)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.RuntimeImageActionResponse{
		Success: true,
		Image:   image,
		Message: "Image pulled",
		Output:  output,
	})
}

// @Summary Remove a runtime image
// @Tags Images
// @Security BearerAuth
// @Produce json
// @Param reference query string true "Image reference or ID"
// @Param force query bool false "Force image removal"
// @Success 200 {object} models.RuntimeImageActionResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 403 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/images [delete]
func RemoveRuntimeImageHandler(c *gin.Context) {
	username := c.GetString("username")
	if !requireSuperuser(c, username, "remove runtime image") {
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	reference := strings.TrimSpace(c.Query("reference"))
	if !isValidRuntimeImageReference(reference) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid image reference"})
		return
	}
	force, err := strconv.ParseBool(c.DefaultQuery("force", "false"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid force parameter"})
		return
	}

	output, err := svc.RemoveRuntimeImage(c.Request.Context(), reference, force)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.RuntimeImageActionResponse{
		Success: true,
		Image:   reference,
		Message: "Image removed",
		Output:  output,
	})
}
