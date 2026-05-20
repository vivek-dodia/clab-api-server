//go:build linux

package api

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openWorkspaceRoot(rootPath string) (*os.Root, error) {
	fd, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: rootPath, Err: err}
	}
	defer unix.Close(fd)

	return os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", fd))
}
