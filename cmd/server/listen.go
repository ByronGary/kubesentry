package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// socketMode is the permission of a Unix socket listener: the owner and its
// group (the pod's fsGroup, shared with the oauth2-proxy sidecar) may
// connect, nobody else.
const socketMode fs.FileMode = 0o660

// unixSocketPath returns the socket path of a "unix:///path" listen address.
func unixSocketPath(addr string) (string, bool) {
	return strings.CutPrefix(addr, "unix://")
}

// validSocketPath checks a Unix socket path from a listen address.
func validSocketPath(path string) error {
	switch {
	case path == "" || !filepath.IsAbs(path):
		return fmt.Errorf("unix socket path %q must be absolute, as in unix:///var/run/kubesentry/web.sock", path)
	case len(path) > 100:
		return fmt.Errorf("unix socket path %q is too long (at most 100 bytes)", path)
	}
	return nil
}

// listen opens addr: TCP host:port, or a Unix socket for "unix:///path".
// A socket file left at the path by a previous run is replaced when nothing
// listens on it any more; anything else at the path (a live socket, a
// regular file) is an error. The socket is chmod'ed to socketMode.
func listen(addr string) (ln net.Listener, unix bool, err error) {
	path, unix := unixSocketPath(addr)
	if !unix {
		ln, err = net.Listen("tcp", addr)
		return ln, false, err
	}
	if err := validSocketPath(path); err != nil {
		return nil, true, err
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, true, err
	}
	ln, err = net.Listen("unix", path)
	if err != nil {
		return nil, true, err
	}
	if err := os.Chmod(path, socketMode); err != nil {
		ln.Close()
		return nil, true, fmt.Errorf("chmod %s: %w", path, err)
	}
	return ln, true, nil
}

// removeStaleSocket deletes a socket file nothing listens on.
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket; refusing to replace it", path)
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return fmt.Errorf("%s is in use by another process", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}
