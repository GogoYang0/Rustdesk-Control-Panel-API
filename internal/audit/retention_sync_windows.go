//go:build windows

package audit

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// syncDir flushes a directory's entries on Windows. A directory cannot be
// opened for GENERIC_WRITE through os.Open, so the handle is created with
// FILE_FLAG_BACKUP_SEMANTICS and flushed with FlushFileBuffers. A failure is
// propagated: without the guarantee the retention worker must keep the
// database rows.
func syncDir(dir string) error {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	if err := syscall.FlushFileBuffers(h); err != nil {
		return &os.PathError{Op: "sync", Path: dir, Err: err}
	}
	return nil
}

// renameDurable publishes oldPath as newPath with MOVEFILE_WRITE_THROUGH, so
// the rename is on disk before the call returns (Go's os.Rename does not set
// that flag).
func renameDurable(oldPath, newPath string) error {
	from, err := syscall.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
