package models

// CustomNodeTemplate stores a user-defined TopoViewer node template.
// It intentionally allows additional arbitrary fields so advanced node
// template settings survive round-trips through the API.
type CustomNodeTemplate map[string]interface{}

// CustomNodesResponse returns the current custom node template set and the
// derived default node name.
type CustomNodesResponse struct {
	CustomNodes []CustomNodeTemplate `json:"customNodes"`
	DefaultNode string               `json:"defaultNode"`
}

// CustomNodesReplaceRequest replaces the full custom node template collection.
type CustomNodesReplaceRequest struct {
	CustomNodes []CustomNodeTemplate `json:"customNodes"`
}

// CustomNodeDefaultRequest selects the default custom node template by name.
type CustomNodeDefaultRequest struct {
	Name string `json:"name" binding:"required"`
}

// CustomIconInfo describes a custom icon exposed to the TopoViewer UI.
type CustomIconInfo struct {
	Name    string `json:"name"`
	Source  string `json:"source" example:"global"`
	DataURI string `json:"dataUri"`
	Format  string `json:"format" example:"svg"`
}

// IconListResponse returns a list of custom icons.
type IconListResponse struct {
	Icons []CustomIconInfo `json:"icons"`
}

// IconUploadRequest uploads a new global custom icon.
type IconUploadRequest struct {
	FileName    string `json:"fileName" binding:"required" example:"my-router.svg"`
	ContentType string `json:"contentType,omitempty" example:"image/svg+xml"`
	DataBase64  string `json:"dataBase64" binding:"required"`
}

// IconUploadResponse reports the final stored icon name after upload.
type IconUploadResponse struct {
	Success  bool   `json:"success" example:"true"`
	IconName string `json:"iconName" example:"my-router"`
}

// IconReconcileRequest describes the custom icon names currently used by a lab.
type IconReconcileRequest struct {
	UsedIcons []string `json:"usedIcons"`
}
