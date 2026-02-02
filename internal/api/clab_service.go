// internal/api/clab_service.go
package api

import (
	"github.com/srl-labs/clab-api-server/internal/clab"
)

// clabService is the global containerlab service instance.
var clabService *clab.Service

// SetClabService sets the containerlab service instance for use by handlers.
func SetClabService(svc *clab.Service) {
	clabService = svc
}

// GetClabService returns the containerlab service instance.
func GetClabService() *clab.Service {
	return clabService
}
