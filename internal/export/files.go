package export

import (
	"io"
	"os"
)

// File is a file being written. Sync is called before Close on everything the
// exporter writes, so a crash cannot leave a manifest naming unflushed data.
type File interface {
	io.Writer
	Sync() error
	Close() error
}

// FS is the filesystem the exporter writes through. Tests substitute one that
// fails at a chosen step; that is how a failed write is proven to end as a
// failure rather than as a manifest describing files that are not there.
type FS interface {
	MkdirAll(path string, perm os.FileMode) error
	MkdirTemp(dir, pattern string) (string, error)
	Create(path string) (File, error)
	Open(path string) (io.ReadCloser, error)
	Rename(oldpath, newpath string) error
	RemoveAll(path string) error
	Stat(path string) (os.FileInfo, error)
}

// OSFS writes to the real filesystem, owner-only: exports hold job records.
type OSFS struct{}

func (OSFS) MkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (OSFS) MkdirTemp(dir, pattern string) (string, error) {
	return os.MkdirTemp(dir, pattern) // created 0700
}
func (OSFS) Create(path string) (File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}
func (OSFS) Open(path string) (io.ReadCloser, error) { return os.Open(path) }
func (OSFS) Rename(oldpath, newpath string) error    { return os.Rename(oldpath, newpath) }
func (OSFS) RemoveAll(path string) error             { return os.RemoveAll(path) }
func (OSFS) Stat(path string) (os.FileInfo, error)   { return os.Stat(path) }
