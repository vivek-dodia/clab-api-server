//go:build !linux

package api

import "os"

func openWorkspaceRoot(rootPath string) (*os.Root, error) {
	return os.OpenRoot(rootPath)
}
