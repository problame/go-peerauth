package peerauth

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

// writeJob is to be used in conjunction with writeJobs
type writeJob struct {
	path string
	mode uint32
	buf  []byte
	f    *os.File
}

func newWriteJob(path string, mode uint32) *writeJob {
	return &writeJob{path, mode, nil, nil}
}

func (o *writeJob) SetWriteData(buf []byte) { o.buf = buf }

func (o *writeJob) Path() string { return o.path }

func (o *writeJob) rollback() error {
	if o.f != nil {
		if err := o.f.Close(); err != nil {
			return err
		}
		os.Remove(o.path) // ignore error
		o.f = nil
	}
	return nil
}

// writeJobs implements atomic non-overwriting write of several instances of *writeJob to the filesystem.
//
// If one writeJob fails, e.g. because the target writeJob.Path() already exists or an IO error occured,
// all previously created files are removed.
// Failed removals are silently ignored.
type writeJobs []*writeJob

func (w writeJobs) Close() error {
	var lastErr error = nil
	for _, out := range w {
		if out.f != nil {
			if err := out.f.Close(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

func (w writeJobs) Open() error {
	rollback := func() {
		for _, o := range w {
			o.rollback()
		}
	}
	for _, out := range w {
		fd, err := unix.Open(out.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, out.mode)
		if err != nil {
			rollback()
			return fmt.Errorf("cannot open %q for creation: %s", out.path, err)
		}
		out.f = os.NewFile(uintptr(fd), out.path)
		if out.f == nil {
			rollback()
			return fmt.Errorf("cannot convert fd to *os.File")
		}
	}
	return nil
}

func (w writeJobs) WriteOut() error {
	rollback := func() {
		for _, o := range w {
			o.rollback()
		}
	}
	for _, out := range w {
		if _, err := io.Copy(out.f, bytes.NewBuffer(out.buf)); err != nil {
			rollback()
			return fmt.Errorf("error writing file %q: %s", out.path, err)
		}
	}
	return nil
}
