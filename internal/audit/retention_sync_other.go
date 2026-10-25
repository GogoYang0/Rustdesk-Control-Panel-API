//go:build !windows

package audit

import "os"

// syncDir flushes a directory's entries so a rename survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// renameDurable publishes oldPath as newPath; the caller syncs the directory
// afterwards to make the entry durable.
func renameDurable(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}
