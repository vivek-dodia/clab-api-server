// internal/clab/converters.go
package clab

import (
	"encoding/json"

	clabconst "github.com/srl-labs/containerlab/constants"
	clabexec "github.com/srl-labs/containerlab/exec"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"

	"github.com/srl-labs/clab-api-server/internal/models"
)

// ContainerToClabContainerInfo converts a containerlab GenericContainer to API ClabContainerInfo.
func ContainerToClabContainerInfo(c clabruntime.GenericContainer) models.ClabContainerInfo {
	name := ""
	if len(c.Names) > 0 {
		name = c.Names[0]
	}
	return models.ClabContainerInfo{
		Name:        name,
		ContainerID: c.ShortID,
		Image:       c.Image,
		Kind:        c.Labels[clabconst.NodeKind],
		State:       c.State,
		Status:      c.Status,
		IPv4Address: c.GetContainerIPv4(),
		IPv6Address: c.GetContainerIPv6(),
		LabName:     c.Labels[clabconst.Containerlab],
		LabPath:     c.Labels[clabconst.TopoFile],
		AbsLabPath:  c.Labels[clabconst.TopoFile],
		Group:       c.Labels[clabconst.NodeGroup],
		Owner:       c.Labels[clabconst.Owner],
	}
}

// ContainersToClabInspectOutput converts a slice of containers to the API inspect output format.
func ContainersToClabInspectOutput(containers []clabruntime.GenericContainer) models.ClabInspectOutput {
	result := make(models.ClabInspectOutput)

	for _, c := range containers {
		labName := c.Labels[clabconst.Containerlab]
		if labName == "" {
			continue
		}

		containerInfo := ContainerToClabContainerInfo(c)
		result[labName] = append(result[labName], containerInfo)
	}

	return result
}

// ContainerInterfacesToNodeInterfaceInfo converts containerlab interfaces to API format.
func ContainerInterfacesToNodeInterfaceInfo(ci *clabtypes.ContainerInterfaces) models.NodeInterfaceInfo {
	var interfaces []models.InterfaceInfo

	for _, iface := range ci.Interfaces {
		interfaces = append(interfaces, models.InterfaceInfo{
			Name:    iface.InterfaceName,
			Alias:   iface.InterfaceAlias,
			Mac:     iface.InterfaceMAC,
			IfIndex: iface.InterfaceIndex,
			Mtu:     iface.InterfaceMTU,
			Type:    iface.InterfaceType,
			State:   iface.InterfaceState,
		})
	}

	return models.NodeInterfaceInfo{
		NodeName:   ci.ContainerName,
		Interfaces: interfaces,
	}
}

// ContainersInterfacesToInspectOutput converts a slice of container interfaces to API format.
func ContainersInterfacesToInspectOutput(cis []*clabtypes.ContainerInterfaces) models.ClabInspectInterfacesOutput {
	var result models.ClabInspectInterfacesOutput

	for _, ci := range cis {
		if ci != nil {
			result = append(result, ContainerInterfacesToNodeInterfaceInfo(ci))
		}
	}

	return result
}

// ExecCollectionToExecResponse converts containerlab exec results to API format.
func ExecCollectionToExecResponse(ec *clabexec.ExecCollection) models.ExecResponse {
	result := make(models.ExecResponse)

	if ec == nil {
		return result
	}

	// Use the Dump method to get JSON representation and unmarshal it
	// This is the only way to access the private execEntries map
	jsonStr, err := ec.Dump("json")
	if err != nil || jsonStr == "" {
		return result
	}

	// Define intermediate type matching ExecResult structure from containerlab
	// Note: containerlab uses capital case in JSON output
	type execResult struct {
		Cmd        []string `json:"Cmd"`
		ReturnCode int      `json:"ReturnCode"`
		Stdout     string   `json:"Stdout"`
		Stderr     string   `json:"Stderr"`
	}

	// Unmarshal JSON to map
	var rawResults map[string][]*execResult
	if err := json.Unmarshal([]byte(jsonStr), &rawResults); err != nil {
		return result
	}

	// Convert to API format
	for nodeName, execResults := range rawResults {
		var nodeResults []models.ClabExecInternalResult
		for _, er := range execResults {
			nodeResults = append(nodeResults, models.ClabExecInternalResult{
				Cmd:        er.Cmd,
				ReturnCode: er.ReturnCode,
				Stdout:     er.Stdout,
				Stderr:     er.Stderr,
			})
		}
		result[nodeName] = nodeResults
	}

	return result
}

// GetContainerName safely extracts the container name from a GenericContainer.
func GetContainerName(c *clabruntime.GenericContainer) string {
	if c == nil || len(c.Names) == 0 {
		return ""
	}
	return c.Names[0]
}

// GetContainerLabName extracts the lab name from a container's labels.
func GetContainerLabName(c *clabruntime.GenericContainer) string {
	if c == nil {
		return ""
	}
	return c.Labels[clabconst.Containerlab]
}

// GetContainerOwner extracts the owner from a container's labels.
func GetContainerOwner(c *clabruntime.GenericContainer) string {
	if c == nil {
		return ""
	}
	return c.Labels[clabconst.Owner]
}

// GetContainerTopoPath extracts the topology path from a container's labels.
func GetContainerTopoPath(c *clabruntime.GenericContainer) string {
	if c == nil {
		return ""
	}
	return c.Labels[clabconst.TopoFile]
}

// FilterContainersByOwner filters containers by owner.
func FilterContainersByOwner(containers []clabruntime.GenericContainer, owner string) []clabruntime.GenericContainer {
	var result []clabruntime.GenericContainer

	for _, c := range containers {
		if c.Labels[clabconst.Owner] == owner {
			result = append(result, c)
		}
	}

	return result
}

// FilterContainersByLab filters containers by lab name.
func FilterContainersByLab(containers []clabruntime.GenericContainer, labName string) []clabruntime.GenericContainer {
	var result []clabruntime.GenericContainer

	for _, c := range containers {
		if c.Labels[clabconst.Containerlab] == labName {
			result = append(result, c)
		}
	}

	return result
}

// FindContainerByName finds a container by its name in a slice.
func FindContainerByName(containers []clabruntime.GenericContainer, name string) *clabruntime.GenericContainer {
	for i := range containers {
		for _, n := range containers[i].Names {
			if n == name {
				return &containers[i]
			}
		}
		if containers[i].ShortID == name {
			return &containers[i]
		}
	}
	return nil
}

// GroupContainersByLab groups containers by their lab name.
func GroupContainersByLab(containers []clabruntime.GenericContainer) map[string][]clabruntime.GenericContainer {
	result := make(map[string][]clabruntime.GenericContainer)

	for _, c := range containers {
		labName := c.Labels[clabconst.Containerlab]
		if labName != "" {
			result[labName] = append(result[labName], c)
		}
	}

	return result
}
