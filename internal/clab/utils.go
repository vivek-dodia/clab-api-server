// internal/clab/utils.go
package clab

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/log"
)

// SanitizePath prevents path traversal.
// Returns the cleaned path if valid, otherwise an error.
func SanitizePath(relativePath string) (string, error) {
	// Clean the input path first (removes redundant slashes, dots)
	cleanedPath := filepath.Clean(relativePath)

	// Security Check: Prevent absolute paths or paths starting with '../' in the input
	// Allow paths starting with './' or just filename.
	if filepath.IsAbs(cleanedPath) || strings.HasPrefix(cleanedPath, ".."+string(filepath.Separator)) || cleanedPath == ".." {
		log.Warn("Path traversal attempt blocked", "requested_path", relativePath, "cleaned_path", cleanedPath)
		return "", fmt.Errorf("invalid path: '%s' must be relative and cannot start with '..'", relativePath)
	}

	log.Debug("Sanitized path", "original", relativePath, "cleaned", cleanedPath)
	return cleanedPath, nil
}
