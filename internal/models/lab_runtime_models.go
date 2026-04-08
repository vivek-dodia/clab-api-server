package models

type NodeBrowserPort struct {
	HostIP        string `json:"hostIp,omitempty"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
	Description   string `json:"description,omitempty"`
}

type NodeBrowserPortsResponse struct {
	NodeName      string            `json:"nodeName"`
	ContainerName string            `json:"containerName"`
	Ports         []NodeBrowserPort `json:"ports"`
}

type ShareToolResponse struct {
	Message string `json:"message"`
	Link    string `json:"link,omitempty"`
	Output  string `json:"output,omitempty"`
}

type FcliCommandRequest struct {
	Command string `json:"command" binding:"required"`
}

type FcliCommandResponse struct {
	Command string `json:"command"`
	Output  string `json:"output"`
}

type DrawioGenerateRequest struct {
	Layout string `json:"layout,omitempty" example:"horizontal"`
	Theme  string `json:"theme,omitempty" example:"nokia_modern"`
}

type DrawioGenerateResponse struct {
	FileName string `json:"fileName"`
	Content  string `json:"content"`
	Layout   string `json:"layout"`
	Message  string `json:"message,omitempty"`
	Output   string `json:"output,omitempty"`
}

type CaptureCloseAllResponse struct {
	Message string `json:"message"`
	Closed  int    `json:"closed"`
}
