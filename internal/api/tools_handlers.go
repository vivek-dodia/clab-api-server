// internal/api/tools_handlers.go
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// --- TX Offload Handler ---

// @Summary Disable TX checksum offload
// @Description Disables TX checksum offload on the eth0 interface of a container. Requires superuser privileges.
// @Tags Tools
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param tx_request body models.DisableTxOffloadRequest true "Container Name"
// @Success 200 {object} models.GenericSuccessResponse "Offload disabled successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/tools/disable-tx-offload [post]
func DisableTxOffloadHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !requireSuperuser(c, username, "use disable-tx-offload") {
		return
	}

	var req models.DisableTxOffloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("DisableTxOffload failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	if !isValidContainerName(req.ContainerName) {
		log.Warnf("DisableTxOffload failed for superuser '%s': Invalid container name format '%s'", username, req.ContainerName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid container name format."})
		return
	}

	_, err := verifyContainerOwnership(c, username, req.ContainerName)
	if err != nil {
		// verifyContainerOwnership already sent the response (404 or 500)
		return
	}

	// --- Execute using service ---
	svc := GetClabService()
	log.Infof("Superuser '%s' executing disable-tx-offload for container '%s'", username, req.ContainerName)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err = svc.DisableTxOffload(ctx, clab.DisableTxOffloadOptions{
		ContainerName: req.ContainerName,
		InterfaceName: "eth0",
	})

	if err != nil {
		log.Errorf("DisableTxOffload failed for container '%s' (user '%s'): %v", req.ContainerName, username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("Failed to disable TX offload for container '%s': %s", req.ContainerName, err.Error()),
		})
		return
	}

	log.Infof("Successfully disabled TX offload for container '%s' (triggered by superuser '%s')", req.ContainerName, username)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{
		Message: fmt.Sprintf("TX checksum offload disabled successfully for eth0 on container '%s'", req.ContainerName),
	})
}

// --- Certificate Handlers ---

// @Summary Create certificate authority (CA)
// @Description Creates a CA certificate and private key. Requires superuser privileges.
// @Description
// @Description **Notes**
// @Description - Files are stored in the user's `~/.clab/certs/<ca_name>/` directory on the server.
// @Tags Tools - Certificates
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param ca_request body models.CACreateRequest true "CA Generation Parameters"
// @Success 200 {object} models.CertResponse "CA created successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 500 {object} models.ErrorResponse "Internal server error (filesystem, clab execution)"
// @Router /api/v1/tools/certs/ca [post]
func CreateCAHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !requireSuperuser(c, username, "use cert ca create") {
		return
	}

	var req models.CACreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("CreateCA failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Validate and Set Defaults ---
	caName := strings.TrimSpace(req.Name)
	if caName == "" {
		caName = "ca" // Default name
	}
	if !isValidCertName(caName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid CA name format."})
		return
	}

	expiry := strings.TrimSpace(req.Expiry)
	if expiry == "" {
		expiry = "87600h" // Default expiry (10 years)
	}
	if !isValidDurationString(expiry) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid expiry duration format."})
		return
	}

	// --- Path Handling & Ownership Setup ---
	basePath, err := getUserCertBasePath(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	// Get user UID/GID for Chown operations
	usr, lookupErr := user.Lookup(username)
	uid, uidErr := -1, fmt.Errorf("user lookup failed")
	gid, gidErr := -1, fmt.Errorf("user lookup failed")
	if lookupErr == nil {
		uid, uidErr = strconv.Atoi(usr.Uid)
		gid, gidErr = strconv.Atoi(usr.Gid)
	}
	canChown := lookupErr == nil && uidErr == nil && gidErr == nil
	if !canChown {
		log.Warnf("CreateCA: Cannot reliably get UID/GID for user '%s'. Ownership of generated files might be incorrect.", username)
	}

	// Create the specific subdirectory for this CA
	caDir := filepath.Join(basePath, caName)
	if err := os.MkdirAll(caDir, 0750); err != nil {
		log.Errorf("Failed to create CA subdirectory '%s': %v", caDir, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to create CA directory"})
		return
	}

	// Set ownership of the CA directory
	if canChown {
		if err := os.Chown(caDir, uid, gid); err != nil {
			log.Warnf("Failed to set ownership of CA directory '%s' to user '%s': %v. Continuing...", caDir, username, err)
		} else {
			log.Debugf("Set ownership of CA directory '%s' to user '%s'", caDir, username)
		}
	}

	// Parse expiry duration
	expiryDuration, err := parseExpiryDuration(expiry)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid expiry duration: " + err.Error()})
		return
	}

	// --- Execute using service ---
	svc := GetClabService()
	log.Infof("Superuser '%s' creating CA '%s' in user's path '%s'", username, caName, caDir)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, err = svc.CreateCA(ctx, clab.CACreateOptions{
		Name:         caName,
		Expiry:       expiryDuration,
		CommonName:   req.CommonName,
		Country:      req.Country,
		Locality:     req.Locality,
		Organization: req.Organization,
		OrgUnit:      req.OrgUnit,
		OutputPath:   caDir,
	})

	if err != nil {
		log.Errorf("CreateCA failed for CA '%s' (user '%s'): %v", caName, username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("Failed to create CA '%s': %s", caName, err.Error()),
		})
		return
	}

	// --- Attempt to set ownership of generated files ---
	if canChown {
		certFilePath := filepath.Join(caDir, caName+".pem")
		keyFilePath := filepath.Join(caDir, caName+".key")
		csrFilePath := filepath.Join(caDir, caName+".csr")

		for _, fPath := range []string{certFilePath, keyFilePath, csrFilePath} {
			if _, statErr := os.Stat(fPath); statErr == nil {
				if chownErr := os.Chown(fPath, uid, gid); chownErr != nil {
					log.Warnf("Failed to set ownership of generated file '%s' to user '%s': %v", fPath, username, chownErr)
				} else {
					log.Debugf("Set ownership of generated file '%s' to user '%s'", fPath, username)
				}
			}
		}
	}

	log.Infof("Successfully created CA '%s' for superuser '%s' in user directory", caName, username)

	// Construct relative paths for response
	certRelPath := filepath.Join(caName, caName+".pem")
	keyRelPath := filepath.Join(caName, caName+".key")
	csrRelPath := filepath.Join(caName, caName+".csr")

	c.JSON(http.StatusOK, models.CertResponse{
		Message:  fmt.Sprintf("CA '%s' created successfully in user's cert directory.", caName),
		CertPath: certRelPath,
		KeyPath:  keyRelPath,
		CSRPath:  csrRelPath,
	})
}

// @Summary Sign certificate
// @Description Creates a certificate/key and signs it with a previously generated CA. Requires superuser privileges.
// @Description
// @Description **Notes**
// @Description - Files are stored in the user's `~/.clab/certs/<ca_name>/` directory.
// @Tags Tools - Certificates
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param sign_request body models.CertSignRequest true "Certificate Signing Parameters"
// @Success 200 {object} models.CertResponse "Certificate signed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters (name, hosts, CA name, etc.)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 404 {object} models.ErrorResponse "Specified CA not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error (filesystem, clab execution)"
// @Router /api/v1/tools/certs/sign [post]
func SignCertHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !requireSuperuser(c, username, "use cert sign") {
		return
	}

	var req models.CertSignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("SignCert failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Validate Inputs ---
	certName := strings.TrimSpace(req.Name)
	if !isValidCertName(certName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid certificate name format."})
		return
	}
	caName := strings.TrimSpace(req.CaName)
	if !isValidCertName(caName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid CA name format."})
		return
	}
	if len(req.Hosts) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "At least one host (SAN) is required."})
		return
	}
	// Basic validation for hosts
	for _, h := range req.Hosts {
		if strings.ContainsAny(h, " ,;\"'()") {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Invalid character in host entry: '%s'", h)})
			return
		}
	}

	keySize := req.KeySize
	if keySize == 0 {
		keySize = 2048
	} else if keySize < 2048 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Key size must be 2048 or greater."})
		return
	}

	commonName := strings.TrimSpace(req.CommonName)
	if commonName == "" {
		commonName = certName
	}

	// --- Path Handling & Ownership Info ---
	basePath, err := getUserCertBasePath(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	usr, lookupErr := user.Lookup(username)
	uid, uidErr := -1, fmt.Errorf("user lookup failed")
	gid, gidErr := -1, fmt.Errorf("user lookup failed")
	if lookupErr == nil {
		uid, uidErr = strconv.Atoi(usr.Uid)
		gid, gidErr = strconv.Atoi(usr.Gid)
	}
	canChown := lookupErr == nil && uidErr == nil && gidErr == nil
	if !canChown {
		log.Warnf("SignCert: Cannot reliably get UID/GID for user '%s'. Ownership of generated files might be incorrect.", username)
	}

	// Certs are stored within the CA's subdirectory
	caDir := filepath.Join(basePath, caName)
	caCertPath := filepath.Join(caDir, caName+".pem")
	caKeyPath := filepath.Join(caDir, caName+".key")

	// Check if CA files exist
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		log.Warnf("SignCert failed for user '%s': CA certificate not found at '%s'", username, caCertPath)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("CA '%s' certificate not found in user's cert directory.", caName)})
		return
	}
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		log.Warnf("SignCert failed for user '%s': CA key not found at '%s'", username, caKeyPath)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("CA '%s' key not found in user's cert directory.", caName)})
		return
	}

	// --- Execute using service ---
	svc := GetClabService()
	log.Infof("Superuser '%s' signing certificate '%s' using CA '%s' in user's path '%s'", username, certName, caName, caDir)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, err = svc.SignCert(ctx, clab.CertSignOptions{
		Name:         certName,
		Hosts:        req.Hosts,
		CommonName:   commonName,
		Country:      req.Country,
		Locality:     req.Locality,
		Organization: req.Organization,
		OrgUnit:      req.OrgUnit,
		KeySize:      keySize,
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		OutputPath:   caDir,
	})

	if err != nil {
		log.Errorf("SignCert failed for cert '%s' using CA '%s' (user '%s'): %v", certName, caName, username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("Failed to sign certificate '%s' using CA '%s': %s", certName, caName, err.Error()),
		})
		return
	}

	// --- Attempt to set ownership of generated files ---
	if canChown {
		certFilePath := filepath.Join(caDir, certName+".pem")
		keyFilePath := filepath.Join(caDir, certName+".key")
		csrFilePath := filepath.Join(caDir, certName+".csr")

		for _, fPath := range []string{certFilePath, keyFilePath, csrFilePath} {
			if _, statErr := os.Stat(fPath); statErr == nil {
				if chownErr := os.Chown(fPath, uid, gid); chownErr != nil {
					log.Warnf("Failed to set ownership of generated file '%s' to user '%s': %v", fPath, username, chownErr)
				} else {
					log.Debugf("Set ownership of generated file '%s' to user '%s'", fPath, username)
				}
			}
		}
	}

	log.Infof("Successfully signed certificate '%s' using CA '%s' for superuser '%s' in user directory", certName, caName, username)

	// Construct relative paths for response
	certRelPath := filepath.Join(caName, certName+".pem")
	keyRelPath := filepath.Join(caName, certName+".key")
	csrRelPath := filepath.Join(caName, certName+".csr")

	c.JSON(http.StatusOK, models.CertResponse{
		Message:  fmt.Sprintf("Certificate '%s' signed successfully by CA '%s' in user's cert directory.", certName, caName),
		CertPath: certRelPath,
		KeyPath:  keyRelPath,
		CSRPath:  csrRelPath,
	})
}

// @Summary Create vEth pair
// @Description Creates a virtual Ethernet (vEth) pair between two endpoints (container, host, bridge, or ovs-bridge). Requires superuser privileges.
// @Tags Tools - vEth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param veth_request body models.VethCreateRequest true "vEth Creation Parameters"
// @Success 200 {object} models.GenericSuccessResponse "vEth pair created successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters (endpoints, MTU)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 500 {object} models.ErrorResponse "Internal server error (clab execution failed)"
// @Router /api/v1/tools/veth [post]
func CreateVethHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !requireSuperuser(c, username, "use veth create") {
		return
	}

	var req models.VethCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("CreateVeth failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Validate Inputs ---
	if !isValidVethEndpoint(req.AEndpoint) {
		log.Warnf("CreateVeth failed for superuser '%s': Invalid format for aEndpoint '%s'", username, req.AEndpoint)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Invalid format for aEndpoint: %s", req.AEndpoint)})
		return
	}
	if !isValidVethEndpoint(req.BEndpoint) {
		log.Warnf("CreateVeth failed for superuser '%s': Invalid format for bEndpoint '%s'", username, req.BEndpoint)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Invalid format for bEndpoint: %s", req.BEndpoint)})
		return
	}
	if req.Mtu < 0 {
		log.Warnf("CreateVeth failed for superuser '%s': Invalid MTU value '%d'", username, req.Mtu)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid MTU value. Must be non-negative."})
		return
	}

	// --- Execute using service ---
	svc := GetClabService()
	log.Infof("Superuser '%s' creating vEth pair: %s <--> %s (MTU: %d)", username, req.AEndpoint, req.BEndpoint, req.Mtu)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := svc.CreateVeth(ctx, clab.VethCreateOptions{
		AEndpoint: req.AEndpoint,
		BEndpoint: req.BEndpoint,
		MTU:       req.Mtu,
	})

	if err != nil {
		log.Errorf("CreateVeth failed for superuser '%s': %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("Failed to create vEth pair (%s <--> %s): %s", req.AEndpoint, req.BEndpoint, err.Error()),
		})
		return
	}

	log.Infof("Successfully created vEth pair for superuser '%s': %s <--> %s", username, req.AEndpoint, req.BEndpoint)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{
		Message: fmt.Sprintf("vEth pair created successfully between %s and %s", req.AEndpoint, req.BEndpoint),
	})
}

// --- VxLAN Handlers ---

// @Summary Create VxLAN tunnel
// @Description Creates a VxLAN tunnel interface and sets up tc rules for traffic redirection. Requires superuser privileges.
// @Tags Tools - VxLAN
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param vxlan_request body models.VxlanCreateRequest true "VxLAN Creation Parameters"
// @Success 200 {object} models.GenericSuccessResponse "VxLAN tunnel created successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters (remote, link, id, port, etc.)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 500 {object} models.ErrorResponse "Internal server error (clab execution failed)"
// @Router /api/v1/tools/vxlan [post]
func CreateVxlanHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !requireSuperuser(c, username, "use vxlan create") {
		return
	}

	var req models.VxlanCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("CreateVxlan failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Validate Inputs ---
	if !isValidIPAddress(req.Remote) {
		log.Warnf("CreateVxlan failed for superuser '%s': Invalid remote IP address format '%s'", username, req.Remote)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid remote IP address format."})
		return
	}
	if !isValidInterfaceName(req.Link) {
		log.Warnf("CreateVxlan failed for superuser '%s': Invalid link interface name format '%s'", username, req.Link)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid link interface name format."})
		return
	}
	if req.ID < 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid VNI (id). Must be non-negative."})
		return
	}
	if req.Port < 0 || req.Port > 65535 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid port number. Must be between 0 and 65535."})
		return
	}
	if req.Dev != "" && !isValidInterfaceName(req.Dev) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid device (dev) name format."})
		return
	}
	if req.Mtu < 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid MTU value. Must be non-negative."})
		return
	}

	// --- Execute using service ---
	svc := GetClabService()
	log.Infof("Superuser '%s' creating VxLAN tunnel: remote=%s, link=%s, id=%d, port=%d", username, req.Remote, req.Link, req.ID, req.Port)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := svc.CreateVxlan(ctx, clab.VxlanCreateOptions{
		Remote:       req.Remote,
		Link:         req.Link,
		ID:           req.ID,
		DstPort:      req.Port,
		ParentDevice: req.Dev,
		MTU:          req.Mtu,
	})

	if err != nil {
		log.Errorf("CreateVxlan failed for superuser '%s': %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("Failed to create VxLAN tunnel (remote: %s, link: %s): %s", req.Remote, req.Link, err.Error()),
		})
		return
	}

	log.Infof("Successfully created VxLAN tunnel for superuser '%s': remote=%s, link=%s", username, req.Remote, req.Link)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{
		Message: fmt.Sprintf("VxLAN tunnel created successfully for link %s to remote %s", req.Link, req.Remote),
	})
}

// @Summary Delete VxLAN tunnels by prefix
// @Description Deletes VxLAN tunnel interfaces that match the provided prefix (default: `vx-`). Requires superuser privileges.
// @Tags Tools - VxLAN
// @Security BearerAuth
// @Produce json
// @Param prefix query string false "Prefix of VxLAN interfaces to delete" default(vx-) example="vx-"
// @Success 200 {object} models.GenericSuccessResponse "VxLAN tunnels deleted successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid prefix format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 500 {object} models.ErrorResponse "Internal server error (clab execution failed)"
// @Router /api/v1/tools/vxlan [delete]
func DeleteVxlanHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !requireSuperuser(c, username, "use vxlan delete") {
		return
	}

	// --- Get and Validate Query Param ---
	prefix := c.DefaultQuery("prefix", "vx-")
	if !isValidPrefix(prefix) {
		log.Warnf("DeleteVxlan failed for superuser '%s': Invalid prefix format '%s'", username, prefix)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid prefix format."})
		return
	}

	// --- Execute using service ---
	svc := GetClabService()
	log.Infof("Superuser '%s' deleting VxLAN tunnels with prefix '%s'", username, prefix)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	deleted, err := svc.DeleteVxlan(ctx, prefix)
	if err != nil {
		log.Errorf("DeleteVxlan failed for superuser '%s' (prefix '%s'): %v", username, prefix, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("Failed to delete VxLAN tunnels with prefix '%s': %s", prefix, err.Error()),
		})
		return
	}

	if len(deleted) == 0 {
		log.Infof("DeleteVxlan for superuser '%s': No VxLAN interfaces found with prefix '%s' to delete.", username, prefix)
		c.JSON(http.StatusOK, models.GenericSuccessResponse{
			Message: fmt.Sprintf("No VxLAN interfaces found with prefix '%s' to delete.", prefix),
		})
		return
	}

	log.Infof("Successfully deleted VxLAN tunnels with prefix '%s' for superuser '%s': %v", prefix, username, deleted)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{
		Message: fmt.Sprintf("Successfully deleted VxLAN interface(s): %s", strings.Join(deleted, ", ")),
	})
}

// --- Netem Handlers ---

// @Summary Set link impairments (netem)
// @Description Sets netem impairments (delay, jitter, loss, rate limiting, corruption) on a specific interface of a containerlab node. Requires superuser privileges.
// @Tags Tools - Netem
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param netem_set_request body models.NetemSetRequest true "Netem Set Parameters"
// @Success 200 {object} models.GenericSuccessResponse "Impairments set successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 404 {object} models.ErrorResponse "Container or interface not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/tools/netem/set [post]
func SetNetemHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !requireSuperuser(c, username, "use netem set") {
		return
	}

	var req models.NetemSetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("SetNetem failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	if !isValidContainerName(req.ContainerName) {
		log.Warnf("SetNetem failed for superuser '%s': Invalid container name format '%s'", username, req.ContainerName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid container name format."})
		return
	}

	iface := strings.TrimSpace(req.Interface)
	if iface == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Interface cannot be empty."})
		return
	}
	// Interface aliases can include spaces/slashes, so keep validation minimal but bounded.
	if len(iface) > 128 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Interface value is too long."})
		return
	}

	var delay, jitter time.Duration
	var err error
	if strings.TrimSpace(req.Delay) != "" {
		delay, err = time.ParseDuration(req.Delay)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid delay duration: " + err.Error()})
			return
		}
	}
	if strings.TrimSpace(req.Jitter) != "" {
		jitter, err = time.ParseDuration(req.Jitter)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid jitter duration: " + err.Error()})
			return
		}
	}
	if jitter != 0 && delay == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Jitter cannot be set without setting delay."})
		return
	}

	if req.Loss < 0 || req.Loss > 100 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Loss must be in the range between 0 and 100."})
		return
	}
	if req.Corruption < 0 || req.Corruption > 100 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Corruption must be in the range between 0 and 100."})
		return
	}

	_, ownerErr := verifyContainerOwnership(c, username, req.ContainerName)
	if ownerErr != nil {
		return
	}

	svc := GetClabService()
	log.Infof("Superuser '%s' setting netem impairments: container=%s interface=%s", username, req.ContainerName, iface)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err = svc.SetNetem(ctx, clab.NetemSetOptions{
		ContainerName: req.ContainerName,
		Interface:     iface,
		Delay:         delay,
		Jitter:        jitter,
		Loss:          req.Loss,
		Rate:          uint64(req.Rate),
		Corruption:    req.Corruption,
	})
	if err != nil {
		if errors.Is(err, clab.ErrNetemInterfaceNotFound) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Interface '%s' not found in container '%s'.", iface, req.ContainerName)})
			return
		}

		log.Errorf("SetNetem failed for superuser '%s' (container '%s', interface '%s'): %v", username, req.ContainerName, iface, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("Failed to set netem impairments for container '%s' interface '%s': %s", req.ContainerName, iface, err.Error()),
		})
		return
	}

	c.JSON(http.StatusOK, models.GenericSuccessResponse{
		Message: fmt.Sprintf("Netem impairments set successfully for container '%s' interface '%s'", req.ContainerName, iface),
	})
}

// @Summary Show link impairments (netem)
// @Description Lists netem impairments for a given containerlab node. Requires superuser privileges.
// @Tags Tools - Netem
// @Security BearerAuth
// @Produce json
// @Param containerName query string true "Container/node name"
// @Success 200 {object} models.NetemShowResponse "Netem impairments"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/tools/netem/show [get]
func ShowNetemHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !requireSuperuser(c, username, "use netem show") {
		return
	}

	containerName := c.Query("containerName")
	if !isValidContainerName(containerName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid container name format."})
		return
	}

	_, ownerErr := verifyContainerOwnership(c, username, containerName)
	if ownerErr != nil {
		return
	}

	svc := GetClabService()
	log.Infof("Superuser '%s' showing netem impairments: container=%s", username, containerName)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	impairments, err := svc.ShowNetem(ctx, containerName)
	if err != nil {
		log.Errorf("ShowNetem failed for superuser '%s' (container '%s'): %v", username, containerName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("Failed to show netem impairments for container '%s': %s", containerName, err.Error()),
		})
		return
	}

	infos := make([]models.NetemInterfaceInfo, 0, len(impairments))
	for _, imp := range impairments {
		rate := uint(0)
		if imp.Rate > 0 {
			rate = uint(imp.Rate)
		}

		infos = append(infos, models.NetemInterfaceInfo{
			Interface:  imp.Interface,
			Delay:      imp.Delay,
			Jitter:     imp.Jitter,
			PacketLoss: imp.PacketLoss,
			Rate:       rate,
			Corruption: imp.Corruption,
		})
	}

	c.JSON(http.StatusOK, models.NetemShowResponse{
		containerName: infos,
	})
}

// @Summary Reset link impairments (netem)
// @Description Resets (removes) netem impairments from a specific interface of a containerlab node. Requires superuser privileges.
// @Tags Tools - Netem
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param netem_reset_request body models.NetemResetRequest true "Netem Reset Parameters"
// @Success 200 {object} models.GenericSuccessResponse "Impairments reset successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 404 {object} models.ErrorResponse "Container or interface not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/tools/netem/reset [post]
func ResetNetemHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !requireSuperuser(c, username, "use netem reset") {
		return
	}

	var req models.NetemResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("ResetNetem failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	if !isValidContainerName(req.ContainerName) {
		log.Warnf("ResetNetem failed for superuser '%s': Invalid container name format '%s'", username, req.ContainerName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid container name format."})
		return
	}

	iface := strings.TrimSpace(req.Interface)
	if iface == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Interface cannot be empty."})
		return
	}
	if len(iface) > 128 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Interface value is too long."})
		return
	}

	_, ownerErr := verifyContainerOwnership(c, username, req.ContainerName)
	if ownerErr != nil {
		return
	}

	svc := GetClabService()
	log.Infof("Superuser '%s' resetting netem impairments: container=%s interface=%s", username, req.ContainerName, iface)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := svc.ResetNetem(ctx, req.ContainerName, iface)
	if err != nil {
		if errors.Is(err, clab.ErrNetemInterfaceNotFound) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Interface '%s' not found in container '%s'.", iface, req.ContainerName)})
			return
		}

		log.Errorf("ResetNetem failed for superuser '%s' (container '%s', interface '%s'): %v", username, req.ContainerName, iface, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("Failed to reset netem impairments for container '%s' interface '%s': %s", req.ContainerName, iface, err.Error()),
		})
		return
	}

	c.JSON(http.StatusOK, models.GenericSuccessResponse{
		Message: fmt.Sprintf("Netem impairments reset successfully for container '%s' interface '%s'", req.ContainerName, iface),
	})
}
