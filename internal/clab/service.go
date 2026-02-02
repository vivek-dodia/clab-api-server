// internal/clab/service.go
package clab

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/containernetworking/plugins/pkg/ns"
	clabcert "github.com/srl-labs/containerlab/cert"
	clabcore "github.com/srl-labs/containerlab/core"
	clabexec "github.com/srl-labs/containerlab/exec"
	clabgit "github.com/srl-labs/containerlab/git"
	clablinks "github.com/srl-labs/containerlab/links"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabnodesstate "github.com/srl-labs/containerlab/nodes/state"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
	clabutils "github.com/srl-labs/containerlab/utils"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v2"

	"github.com/srl-labs/clab-api-server/internal/config"
)

const (
	defaultTimeout         = 5 * time.Minute
	gracefulDestroyTimeout = 2 * time.Minute
)

// Service provides an interface to containerlab operations using the library directly.
type Service struct{}

// NewService creates a new containerlab service.
func NewService() *Service {
	return &Service{}
}

// DeployOptions contains options for deploying a lab.
type DeployOptions struct {
	TopoPath        string
	Username        string
	Reconfigure     bool
	MaxWorkers      uint
	ExportTemplate  string
	NodeFilter      []string
	SkipPostDeploy  bool
	SkipLabDirACLs  bool
}

// DestroyOptions contains options for destroying a lab.
type DestroyOptions struct {
	LabName     string
	TopoPath    string
	Username    string
	Graceful    bool
	Cleanup     bool
	KeepMgmtNet bool
	NodeFilter  []string
	MaxWorkers  uint
}

// ListOptions contains options for listing labs/containers.
type ListOptions struct {
	LabName       string
	ContainerName string
	NodeName      string
}

// ExecOptions contains options for executing commands.
type ExecOptions struct {
	TopoPath      string
	LabName       string
	ContainerName string
	NodeName      string
	Commands      []string
	Username      string
}

// SaveOptions contains options for saving lab configuration.
type SaveOptions struct {
	TopoPath   string
	Username   string
	NodeFilter []string
}

// InspectOptions contains options for inspecting labs.
type InspectOptions struct {
	LabName  string
	Username string
	Details  bool
}

// InterfacesOptions contains options for listing interfaces.
type InterfacesOptions struct {
	LabName    string
	Username   string
	NodeFilter string
}

// Deploy deploys a lab using the containerlab library.
func (s *Service) Deploy(ctx context.Context, opts DeployOptions) ([]clabruntime.GenericContainer, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	// Handle GitHub/GitLab URLs by cloning the repo first
	topoPath := opts.TopoPath
	if s.isGitURL(topoPath) {
		log.Debug("Detected git URL, cloning repository", "url", topoPath)
		var gitErr error
		topoPath, gitErr = s.processGitTopoFile(topoPath, workDir)
		if gitErr != nil {
			return nil, fmt.Errorf("failed to process git URL: %w", gitErr)
		}
		log.Debug("Using cloned topology file", "path", topoPath)
	}

	// Change to the work directory for relative path resolution
	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return nil, fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	// Build clab options
	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(topoPath, ""),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{
			Timeout: defaultTimeout,
		}),
		clabcore.WithLabOwner(opts.Username),
	}

	if len(opts.NodeFilter) > 0 {
		clabOpts = append(clabOpts, clabcore.WithNodeFilter(opts.NodeFilter))
	}

	log.Debug("Creating containerlab instance",
		"topoPath", opts.TopoPath,
		"username", opts.Username,
		"runtime", config.AppConfig.ClabRuntime,
	)

	// Create containerlab instance
	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Build deploy options
	deployOpts, err := clabcore.NewDeployOptions(opts.MaxWorkers)
	if err != nil {
		return nil, fmt.Errorf("failed to create deploy options: %w", err)
	}

	deployOpts.SetReconfigure(opts.Reconfigure).
		SetSkipPostDeploy(opts.SkipPostDeploy).
		SetSkipLabDirFileACLs(opts.SkipLabDirACLs)

	if opts.ExportTemplate != "" {
		deployOpts.SetExportTemplate(opts.ExportTemplate)
	}

	log.Info("Deploying lab",
		"username", opts.Username,
		"topoPath", opts.TopoPath,
		"reconfigure", opts.Reconfigure,
	)

	// Deploy the lab
	containers, err := clab.Deploy(ctx, deployOpts)
	if err != nil {
		return nil, fmt.Errorf("deployment failed: %w", err)
	}

	log.Info("Lab deployed successfully",
		"username", opts.Username,
		"containerCount", len(containers),
	)

	return containers, nil
}

// Destroy destroys a lab using the containerlab library.
func (s *Service) Destroy(ctx context.Context, opts DestroyOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return fmt.Errorf("failed to prepare working directory: %w", err)
	}

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	// Build clab options - use topology path if available, otherwise use lab name
	clabTimeout := defaultTimeout
	if opts.Graceful {
		clabTimeout = gracefulDestroyTimeout
	}
	var clabOpts []clabcore.ClabOption
	clabOpts = append(clabOpts, clabcore.WithTimeout(clabTimeout))

	if opts.TopoPath != "" {
		clabOpts = append(clabOpts, clabcore.WithTopoPath(opts.TopoPath, ""))
	} else if opts.LabName != "" {
		clabOpts = append(clabOpts, clabcore.WithTopologyFromLab(opts.LabName))
	} else {
		return fmt.Errorf("either lab name or topology path is required")
	}

	clabOpts = append(clabOpts,
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: clabTimeout}),
	)

	if opts.KeepMgmtNet {
		clabOpts = append(clabOpts, clabcore.WithKeepMgmtNet())
	}

	log.Debug("Creating containerlab instance for destroy",
		"labName", opts.LabName,
		"topoPath", opts.TopoPath,
		"username", opts.Username,
	)

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Build destroy options
	destroyOpts := []clabcore.DestroyOption{
		clabcore.WithDestroyMaxWorkers(opts.MaxWorkers),
	}

	if opts.Graceful {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyGraceful())
	}

	if opts.Cleanup {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyCleanup())
	}

	if opts.KeepMgmtNet {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyKeepMgmtNet())
	}

	if len(opts.NodeFilter) > 0 {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyNodeFilter(opts.NodeFilter))
	}

	log.Info("Destroying lab",
		"username", opts.Username,
		"labName", opts.LabName,
		"graceful", opts.Graceful,
		"cleanup", opts.Cleanup,
	)

	// Destroy the lab
	if err := clab.Destroy(ctx, destroyOpts...); err != nil {
		return fmt.Errorf("destroy failed: %w", err)
	}

	log.Info("Lab destroyed successfully",
		"username", opts.Username,
		"labName", opts.LabName,
	)

	return nil
}

// ListContainers lists containers matching the given options.
func (s *Service) ListContainers(ctx context.Context, opts ListOptions) ([]clabruntime.GenericContainer, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Create a minimal clab instance for listing (no topology needed)
	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Build list options
	listOpts := []clabcore.ListOption{
		clabcore.WithListclabLabelExists(), // Only list containerlab-managed containers
	}

	if opts.LabName != "" {
		listOpts = append(listOpts, clabcore.WithListLabName(opts.LabName))
	}

	if opts.ContainerName != "" {
		listOpts = append(listOpts, clabcore.WithListContainerName(opts.ContainerName))
	}

	if opts.NodeName != "" {
		listOpts = append(listOpts, clabcore.WithListNodeName(opts.NodeName))
	}

	log.Debug("Listing containers",
		"labName", opts.LabName,
		"containerName", opts.ContainerName,
		"nodeName", opts.NodeName,
	)

	containers, err := clab.ListContainers(ctx, listOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	return containers, nil
}

// ListContainerInterfaces lists interfaces for a specific container.
func (s *Service) ListContainerInterfaces(ctx context.Context, container *clabruntime.GenericContainer) (*clabtypes.ContainerInterfaces, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	interfaces, err := clab.ListContainerInterfaces(ctx, container)
	if err != nil {
		return nil, fmt.Errorf("failed to list container interfaces: %w", err)
	}

	return interfaces, nil
}

// ListContainersInterfaces lists interfaces for multiple containers.
func (s *Service) ListContainersInterfaces(ctx context.Context, containers []clabruntime.GenericContainer) ([]*clabtypes.ContainerInterfaces, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	interfaces, err := clab.ListContainersInterfaces(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers interfaces: %w", err)
	}

	return interfaces, nil
}

// Exec executes commands on containers.
func (s *Service) Exec(ctx context.Context, opts ExecOptions) (*clabexec.ExecCollection, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return nil, fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	// Build clab options
	var clabOpts []clabcore.ClabOption
	clabOpts = append(clabOpts, clabcore.WithTimeout(defaultTimeout))
	if opts.TopoPath != "" {
		clabOpts = append(clabOpts, clabcore.WithTopoPath(opts.TopoPath, ""))
	}
	clabOpts = append(clabOpts,
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	)

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Build list options for targeting containers
	var listOpts []clabcore.ListOption
	if opts.LabName != "" {
		listOpts = append(listOpts, clabcore.WithListLabName(opts.LabName))
	}
	if opts.ContainerName != "" {
		listOpts = append(listOpts, clabcore.WithListContainerName(opts.ContainerName))
	}
	if opts.NodeName != "" {
		listOpts = append(listOpts, clabcore.WithListNodeName(opts.NodeName))
	}

	log.Debug("Executing commands on containers",
		"commands", opts.Commands,
		"labName", opts.LabName,
		"containerName", opts.ContainerName,
	)

	result, err := clab.Exec(ctx, opts.Commands, listOpts...)
	if err != nil {
		return nil, fmt.Errorf("exec failed: %w", err)
	}

	return result, nil
}

// SaveConfig saves the configuration of lab nodes.
func (s *Service) SaveConfig(ctx context.Context, opts SaveOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return fmt.Errorf("failed to prepare working directory: %w", err)
	}

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(opts.TopoPath, ""),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	if len(opts.NodeFilter) > 0 {
		clabOpts = append(clabOpts, clabcore.WithNodeFilter(opts.NodeFilter))
	}

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	log.Info("Saving lab configuration",
		"username", opts.Username,
		"topoPath", opts.TopoPath,
	)

	// Save config for each node
	if err := clab.Save(ctx); err != nil {
		return fmt.Errorf("save failed: %w", err)
	}

	log.Info("Lab configuration saved successfully",
		"username", opts.Username,
	)

	return nil
}

// CACreateOptions contains options for creating a CA.
type CACreateOptions struct {
	Name         string
	Expiry       time.Duration
	CommonName   string
	Country      string
	Locality     string
	Organization string
	OrgUnit      string
	KeySize      int
	OutputPath   string
}

// CreateCA creates a new Certificate Authority.
func (s *Service) CreateCA(ctx context.Context, opts CACreateOptions) (*clabcert.Certificate, error) {
	_, cancel := s.ensureTimeout(ctx)
	defer cancel()

	ca := clabcert.NewCA()

	input := &clabcert.CACSRInput{
		CommonName:       opts.CommonName,
		Country:          opts.Country,
		Locality:         opts.Locality,
		Organization:     opts.Organization,
		OrganizationUnit: opts.OrgUnit,
		Expiry:           opts.Expiry,
		KeySize:          opts.KeySize,
	}

	log.Info("Generating CA certificate",
		"name", opts.Name,
		"commonName", opts.CommonName,
		"expiry", opts.Expiry,
	)

	cert, err := ca.GenerateCACert(input)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	// Write certificate to disk
	certPath := filepath.Join(opts.OutputPath, opts.Name+".pem")
	keyPath := filepath.Join(opts.OutputPath, opts.Name+".key")
	csrPath := filepath.Join(opts.OutputPath, opts.Name+".csr")

	if err := cert.Write(certPath, keyPath, csrPath); err != nil {
		return nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}

	log.Info("CA certificate created successfully",
		"certPath", certPath,
		"keyPath", keyPath,
	)

	return cert, nil
}

// CertSignOptions contains options for signing a certificate.
type CertSignOptions struct {
	Name         string
	Hosts        []string
	CommonName   string
	Country      string
	Locality     string
	Organization string
	OrgUnit      string
	KeySize      int
	CACertPath   string
	CAKeyPath    string
	OutputPath   string
}

// SignCert signs a certificate with a CA.
func (s *Service) SignCert(ctx context.Context, opts CertSignOptions) (*clabcert.Certificate, error) {
	_, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Load CA certificate
	caCert, err := clabcert.NewCertificateFromFile(opts.CACertPath, opts.CAKeyPath, "")
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	ca := clabcert.NewCA()
	if err := ca.SetCACert(caCert); err != nil {
		return nil, fmt.Errorf("failed to set CA certificate: %w", err)
	}

	input := &clabcert.NodeCSRInput{
		Hosts:            opts.Hosts,
		CommonName:       opts.CommonName,
		Country:          opts.Country,
		Locality:         opts.Locality,
		Organization:     opts.Organization,
		OrganizationUnit: opts.OrgUnit,
		KeySize:          opts.KeySize,
	}

	log.Info("Signing certificate",
		"name", opts.Name,
		"hosts", opts.Hosts,
	)

	cert, err := ca.GenerateAndSignNodeCert(input)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Write certificate to disk
	certPath := filepath.Join(opts.OutputPath, opts.Name+".pem")
	keyPath := filepath.Join(opts.OutputPath, opts.Name+".key")
	csrPath := filepath.Join(opts.OutputPath, opts.Name+".csr")

	if err := cert.Write(certPath, keyPath, csrPath); err != nil {
		return nil, fmt.Errorf("failed to write signed certificate: %w", err)
	}

	log.Info("Certificate signed successfully",
		"certPath", certPath,
		"keyPath", keyPath,
	)

	return cert, nil
}

// DisableTxOffloadOptions contains options for disabling TX offload.
type DisableTxOffloadOptions struct {
	ContainerName string
	InterfaceName string
}

// DisableTxOffload disables TX checksum offload on a container's interface.
func (s *Service) DisableTxOffload(ctx context.Context, opts DisableTxOffloadOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Get the runtime - there should be exactly one configured
	var runtime clabruntime.ContainerRuntime
	for _, r := range clab.Runtimes {
		runtime = r
		break
	}
	if runtime == nil {
		return fmt.Errorf("no container runtime configured")
	}

	ifaceName := opts.InterfaceName
	if ifaceName == "" {
		ifaceName = "eth0"
	}

	log.Info("Disabling TX offload",
		"container", opts.ContainerName,
		"interface", ifaceName,
	)

	// Get the container's network namespace path directly from the runtime
	nsPath, err := runtime.GetNSPath(ctx, opts.ContainerName)
	if err != nil {
		return fmt.Errorf("failed to get namespace path for container %s: %w", opts.ContainerName, err)
	}

	// Get the namespace handle and execute the ethtool function
	netns, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open network namespace %s: %w", nsPath, err)
	}
	defer netns.Close()

	// Execute the ethtool function in the container's namespace
	err = netns.Do(clabutils.NSEthtoolTXOff(opts.ContainerName, ifaceName))
	if err != nil {
		return fmt.Errorf("failed to disable TX offload: %w", err)
	}

	log.Info("TX offload disabled successfully",
		"container", opts.ContainerName,
		"interface", ifaceName,
	)

	return nil
}

// VethCreateOptions contains options for creating a veth pair.
type VethCreateOptions struct {
	AEndpoint string
	BEndpoint string
	MTU       int
}

// CreateVeth creates a veth pair between two endpoints.
func (s *Service) CreateVeth(ctx context.Context, opts VethCreateOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	parsedAEnd, err := s.parseVethEndpoint(opts.AEndpoint)
	if err != nil {
		return fmt.Errorf("failed to parse A endpoint: %w", err)
	}

	parsedBEnd, err := s.parseVethEndpoint(opts.BEndpoint)
	if err != nil {
		return fmt.Errorf("failed to parse B endpoint: %w", err)
	}

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Create fake nodes to make links resolve work
	err = s.createVethNodes(ctx, clab, parsedAEnd, parsedBEnd, config.AppConfig.ClabRuntime)
	if err != nil {
		return fmt.Errorf("failed to create nodes: %w", err)
	}

	// Create link brief
	linkBrief := &clablinks.LinkBriefRaw{
		Endpoints: []string{
			fmt.Sprintf("%s:%s", parsedAEnd.Node, parsedAEnd.Iface),
			fmt.Sprintf("%s:%s", parsedBEnd.Node, parsedBEnd.Iface),
		},
		LinkCommonParams: clablinks.LinkCommonParams{
			MTU: opts.MTU,
		},
	}

	linkRaw, err := linkBrief.ToTypeSpecificRawLink()
	if err != nil {
		return fmt.Errorf("failed to convert link brief: %w", err)
	}

	// Copy nodes to links.Nodes
	resolveNodes := make(map[string]clablinks.Node, len(clab.Nodes))
	for k, v := range clab.Nodes {
		resolveNodes[k] = v
	}

	link, err := linkRaw.Resolve(&clablinks.ResolveParams{Nodes: resolveNodes})
	if err != nil {
		return fmt.Errorf("failed to resolve link: %w", err)
	}

	// Deploy the endpoints
	for _, ep := range link.GetEndpoints() {
		ep.Deploy(ctx)
	}

	log.Info("veth pair created successfully",
		"aEndpoint", opts.AEndpoint,
		"bEndpoint", opts.BEndpoint,
	)

	return nil
}

// parsedEndpoint represents a parsed veth endpoint.
type parsedEndpoint struct {
	Node  string
	Iface string
	Kind  clablinks.LinkEndpointType
}

// parseVethEndpoint parses a veth endpoint definition.
func (s *Service) parseVethEndpoint(endpoint string) (parsedEndpoint, error) {
	endpoint = strings.TrimSpace(endpoint)
	ep := parsedEndpoint{}
	arr := strings.Split(endpoint, ":")

	switch len(arr) {
	case 2:
		ep.Kind = clablinks.LinkEndpointTypeVeth
		if arr[0] == "host" {
			ep.Kind = clablinks.LinkEndpointTypeHost
		}
		ep.Node = arr[0]
		ep.Iface = arr[1]
	case 3:
		switch arr[0] {
		case "bridge", "ovs-bridge":
			ep.Kind = clablinks.LinkEndpointTypeBridge
		case "bridge-ns":
			ep.Kind = clablinks.LinkEndpointTypeBridgeNS
		default:
			ep.Kind = clablinks.LinkEndpointTypeVeth
		}
		ep.Node = arr[1]
		ep.Iface = arr[2]
	default:
		return ep, fmt.Errorf("malformed veth endpoint reference: %s", endpoint)
	}

	return ep, nil
}

// createVethNodes creates fake nodes for veth link resolution.
func (s *Service) createVethNodes(ctx context.Context, clab *clabcore.CLab, aEnd, bEnd parsedEndpoint, rt string) error {
	for _, epDef := range []parsedEndpoint{aEnd, bEnd} {
		var kind string
		switch epDef.Kind {
		case clablinks.LinkEndpointTypeHost:
			kind = "host"
		case clablinks.LinkEndpointTypeBridge, clablinks.LinkEndpointTypeBridgeNS:
			kind = "bridge"
		default:
			kind = "linux"
		}

		nodeCfg := &clabtypes.NodeConfig{
			ShortName: epDef.Node,
			LongName:  epDef.Node,
			Runtime:   rt,
		}

		n, err := clab.Reg.NewNodeOfKind(kind)
		if err != nil {
			return fmt.Errorf("error constructing node %s: %w", epDef.Node, err)
		}

		err = n.Init(nodeCfg, clabnodes.WithRuntime(clab.Runtimes[rt]))
		if err != nil {
			return fmt.Errorf("failed to initialize node %s: %w", epDef.Node, err)
		}

		n.SetState(clabnodesstate.Deployed)
		clab.Nodes[epDef.Node] = n
	}

	return nil
}

// VxlanCreateOptions contains options for creating a VxLAN tunnel.
type VxlanCreateOptions struct {
	Remote          string
	Link            string
	ID              int
	DstPort         int
	SrcPort         int
	ParentDevice    string
	MTU             int
}

// CreateVxlan creates a VxLAN tunnel.
func (s *Service) CreateVxlan(ctx context.Context, opts VxlanCreateOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Verify link exists
	if _, err := netlink.LinkByName(opts.Link); err != nil {
		return fmt.Errorf("failed to lookup link %q: %w", opts.Link, err)
	}

	// If parent device not set, find route to remote
	parentDevice := opts.ParentDevice
	if parentDevice == "" {
		r, err := clabutils.GetRouteForIP(net.ParseIP(opts.Remote))
		if err != nil {
			return fmt.Errorf("failed to find route to VxLAN remote address %s: %w", opts.Remote, err)
		}
		parentDevice = r.Interface.Name
	}

	vxlraw := &clablinks.LinkVxlanRaw{
		Remote:          opts.Remote,
		VNI:             opts.ID,
		ParentInterface: parentDevice,
		LinkCommonParams: clablinks.LinkCommonParams{
			MTU: opts.MTU,
		},
		DstPort:  opts.DstPort,
		SrcPort:  opts.SrcPort,
		LinkType: clablinks.LinkTypeVxlanStitch,
		Endpoint: *clablinks.NewEndpointRaw("host", opts.Link, ""),
	}

	rp := &clablinks.ResolveParams{
		Nodes: map[string]clablinks.Node{
			"host": clablinks.GetHostLinkNode(),
		},
		VxlanIfaceNameOverwrite: opts.Link,
	}

	link, err := vxlraw.Resolve(rp)
	if err != nil {
		return fmt.Errorf("failed to resolve VxLAN link: %w", err)
	}

	vxl, ok := link.(*clablinks.VxlanStitched)
	if !ok {
		return fmt.Errorf("resolved link is not a VxlanStitched link")
	}

	err = vxl.DeployWithExistingVeth(ctx)
	if err != nil {
		return fmt.Errorf("failed to deploy VxLAN: %w", err)
	}

	log.Info("VxLAN tunnel created successfully",
		"remote", opts.Remote,
		"link", opts.Link,
		"vni", opts.ID,
	)

	return nil
}

// DeleteVxlan deletes VxLAN tunnels matching a prefix.
func (s *Service) DeleteVxlan(ctx context.Context, prefix string) ([]string, error) {
	_, cancel := s.ensureTimeout(ctx)
	defer cancel()

	ls, err := clabutils.GetLinksByNamePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to get links by prefix: %w", err)
	}

	var deleted []string
	for _, l := range ls {
		if l.Type() != "vxlan" {
			continue
		}

		name := l.Attrs().Name
		log.Info("Deleting VxLAN link", "name", name)

		err := netlink.LinkDel(l)
		if err != nil {
			log.Warn("Error deleting link", "name", name, "error", err)
			continue
		}
		deleted = append(deleted, name)
	}

	return deleted, nil
}

// GenerateTopologyOptions contains options for generating a topology.
type GenerateTopologyOptions struct {
	Name              string
	Tiers             []TierDefinition
	DefaultKind       string
	Images            map[string]string
	Licenses          map[string]string
	NodePrefix        string
	GroupPrefix       string
	ManagementNetwork string
	IPv4Subnet        string
	IPv6Subnet        string
}

// TierDefinition defines a tier in the topology.
type TierDefinition struct {
	Count int
	Kind  string
	Type  string
}

// GenerateTopology generates a topology YAML.
func (s *Service) GenerateTopology(ctx context.Context, opts GenerateTopologyOptions) ([]byte, error) {
	_, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Build nodes definitions
	nodeDefs := make([]nodesDef, len(opts.Tiers))
	for i, tier := range opts.Tiers {
		kind := tier.Kind
		if kind == "" {
			kind = opts.DefaultKind
			if kind == "" {
				kind = "srl"
			}
		}
		nodeDefs[i] = nodesDef{
			numNodes: uint(tier.Count),
			kind:     kind,
			typ:      tier.Type,
		}
	}

	// Get node registry
	clab := &clabcore.CLab{}
	clab.Reg = clabnodes.NewNodeRegistry()
	clab.RegisterNodes()

	// Set default prefixes
	nodePrefix := opts.NodePrefix
	if nodePrefix == "" {
		nodePrefix = "node"
	}
	groupPrefix := opts.GroupPrefix
	if groupPrefix == "" {
		groupPrefix = "tier"
	}

	log.Info("Generating topology",
		"name", opts.Name,
		"tiers", len(opts.Tiers),
	)

	// Generate the topology configuration
	b, err := s.generateTopologyConfig(
		opts.Name,
		opts.ManagementNetwork,
		opts.IPv4Subnet,
		opts.IPv6Subnet,
		opts.Images,
		opts.Licenses,
		clab.Reg,
		nodePrefix,
		groupPrefix,
		nodeDefs...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate topology: %w", err)
	}

	return b, nil
}

// nodesDef is used internally for topology generation.
type nodesDef struct {
	numNodes uint
	kind     string
	typ      string
}

// generateTopologyConfig generates the topology YAML configuration.
func (s *Service) generateTopologyConfig(
	name, network, ipv4range, ipv6range string,
	images, licenses map[string]string,
	reg *clabnodes.NodeRegistry,
	nodePrefix, groupPrefix string,
	nodes ...nodesDef,
) ([]byte, error) {
	numStages := len(nodes)
	config := &clabcore.Config{
		Name: name,
		Mgmt: new(clabtypes.MgmtNet),
		Topology: &clabtypes.Topology{
			Kinds: make(map[string]*clabtypes.NodeDefinition),
			Nodes: make(map[string]*clabtypes.NodeDefinition),
		},
	}

	config.Mgmt.Network = network

	if ipv4range != "" && ipv4range != "<nil>" {
		config.Mgmt.IPv4Subnet = ipv4range
	}

	if ipv6range != "" && ipv6range != "<nil>" {
		config.Mgmt.IPv6Subnet = ipv6range
	}

	for k, img := range images {
		config.Topology.Kinds[k] = &clabtypes.NodeDefinition{Image: img}
	}

	for k, lic := range licenses {
		if knd, ok := config.Topology.Kinds[k]; ok {
			knd.License = lic
			config.Topology.Kinds[k] = knd
			continue
		}
		config.Topology.Kinds[k] = &clabtypes.NodeDefinition{License: lic}
	}

	if numStages == 1 {
		for j := range nodes[0].numNodes {
			node1 := fmt.Sprintf("%s1-%d", nodePrefix, j+1)
			if _, ok := config.Topology.Nodes[node1]; !ok {
				config.Topology.Nodes[node1] = &clabtypes.NodeDefinition{
					Group: fmt.Sprintf("%s-1", groupPrefix),
					Kind:  nodes[0].kind,
					Type:  nodes[0].typ,
				}
			}
		}
	}

	generateNodesAttributes := reg.GetGenerateNodeAttributes()

	for i := range numStages - 1 {
		interfaceOffset := uint(0)
		if i > 0 {
			interfaceOffset = nodes[i-1].numNodes
		}

		for j := range nodes[i].numNodes {
			node1 := fmt.Sprintf("%s%d-%d", nodePrefix, i+1, j+1)
			if _, ok := config.Topology.Nodes[node1]; !ok {
				config.Topology.Nodes[node1] = &clabtypes.NodeDefinition{
					Group: fmt.Sprintf("%s-%d", groupPrefix, i+1),
					Kind:  nodes[i].kind,
					Type:  nodes[i].typ,
				}
			}

			for k := range nodes[i+1].numNodes {
				node2 := fmt.Sprintf("%s%d-%d", nodePrefix, i+2, k+1)
				if _, ok := config.Topology.Nodes[node2]; !ok {
					config.Topology.Nodes[node2] = &clabtypes.NodeDefinition{
						Group: fmt.Sprintf("%s-%d", groupPrefix, i+2),
						Kind:  nodes[i+1].kind,
						Type:  nodes[i+1].typ,
					}
				}

				// Create a raw veth link
				l := &clablinks.LinkVEthRaw{
					Endpoints: []*clablinks.EndpointRaw{
						clablinks.NewEndpointRaw(node1, fmt.Sprintf(
							generateNodesAttributes[nodes[i].kind].GetInterfaceFormat(),
							k+1+interfaceOffset,
						), ""),
						clablinks.NewEndpointRaw(node2, fmt.Sprintf(
							generateNodesAttributes[nodes[i+1].kind].GetInterfaceFormat(),
							j+1,
						), ""),
					},
				}

				ld := &clablinks.LinkDefinition{
					Link: l.ToLinkBriefRaw(),
				}

				config.Topology.Links = append(config.Topology.Links, ld)
			}
		}
	}

	return yaml.Marshal(config)
}

// prepareWorkDir prepares the working directory for a user.
func (s *Service) prepareWorkDir(username string) (string, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("failed to lookup user: %w", err)
	}

	clabDir := filepath.Join(usr.HomeDir, ".clab")
	if err := os.MkdirAll(clabDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create .clab directory: %w", err)
	}

	// Try to set ownership of the .clab directory to the actual user
	uid, uidErr := strconv.Atoi(usr.Uid)
	gid, gidErr := strconv.Atoi(usr.Gid)
	if uidErr == nil && gidErr == nil {
		if chownErr := os.Chown(clabDir, uid, gid); chownErr != nil {
			log.Warn("Failed to set ownership on .clab directory",
				"dir", clabDir,
				"user", username,
				"error", chownErr,
			)
		}
	}

	return clabDir, nil
}

// ensureTimeout ensures the context has a timeout.
func (s *Service) ensureTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return context.WithTimeout(ctx, defaultTimeout)
	}
	return ctx, func() {}
}

// processGitTopoFile handles GitHub/GitLab URLs by cloning the repo and returning
// the local path to the topology file. This mirrors the CLI behavior.
func (s *Service) processGitTopoFile(topo, workDir string) (string, error) {
	// For short github urls, prepend https://github.com
	if clabgit.IsGitHubShortURL(topo) {
		topo = "https://github.com/" + topo
	}

	repo, err := clabgit.NewRepo(topo)
	if err != nil {
		return "", fmt.Errorf("failed to parse git URL: %w", err)
	}

	// Change to workdir so the repo is cloned there
	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return "", fmt.Errorf("failed to change to work directory for git clone: %w", chErr)
	}
	defer func() {
		_ = os.Chdir(originalDir)
	}()

	// Instantiate the git implementation
	gitImpl := clabgit.NewGoGit(repo)

	// Clone the repo
	log.Debug("Cloning git repository", "url", topo, "workDir", workDir)
	if err := gitImpl.Clone(); err != nil {
		return "", fmt.Errorf("failed to clone git repository: %w", err)
	}

	// Adjust permissions for the checked out repo
	if err := clabutils.SetUIDAndGID(repo.GetName()); err != nil {
		log.Warn("Error adjusting repository permissions, continuing anyways", "error", err)
	}

	// Find the topology file in the cloned repo
	repoPath := filepath.Join(workDir, repo.GetName())

	// If a specific path was provided in the URL, use it
	if len(repo.GetPath()) > 0 {
		repoPath = filepath.Join(repoPath, filepath.Join(repo.GetPath()...))
	}

	// If a specific filename was provided, use it
	if repo.GetFilename() != "" {
		topoFile := filepath.Join(repoPath, repo.GetFilename())
		if _, err := os.Stat(topoFile); err != nil {
			return "", fmt.Errorf("specified topology file not found: %s", topoFile)
		}
		return topoFile, nil
	}

	// Otherwise, find a .clab.yml file in the repo
	topoFile, err := clabcore.FindTopoFileByPath(repoPath)
	if err != nil {
		return "", fmt.Errorf("failed to find topology file in cloned repo: %w", err)
	}

	return topoFile, nil
}

// isGitURL checks if the given path is a GitHub or GitLab URL that needs to be cloned.
func (s *Service) isGitURL(path string) bool {
	return clabgit.IsGitHubOrGitLabURL(path) || clabgit.IsGitHubShortURL(path)
}
