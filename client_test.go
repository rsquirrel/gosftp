// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package sftp

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

type testSFTP struct {
	*Client
	cmd *exec.Cmd
}

func newTestSFTP(t *testing.T) *testSFTP {
	sftp := testSFTP{
		Client: &Client{
			chans: &fxpChanList{},
		},
		// cmd: exec.Command("/usr/lib/openssh/sftp-server", "-u", "0", "-e", "-l", "DEBUG3"),
		// TODO(ekg): make the path to the binary a flag.
		cmd: exec.Command("/home/ekg/Downloads/openssh-6.5p1/sftp-server", "-u", "0", "-e", "-l", "DEBUG3"),
	}
	var err error
	if sftp.stdin, err = sftp.cmd.StdinPipe(); err != nil {
		t.Fatalf("sftp.cmd.StdinPipe() = _, %v want nil", err)
	}
	if sftp.stdout, err = sftp.cmd.StdoutPipe(); err != nil {
		t.Fatalf("sftp.cmd.StdoutPipe() = _, %v want nil", err)
	}
	sftp.cmd.Stderr = os.Stderr
	if err := sftp.cmd.Start(); err != nil {
		t.Fatalf("sftp.cmd.Start() = %v, want nil", err)
	}
	if err := sftp.init(); err != nil {
		t.Fatalf("sftp.init() = %v, want nil", err)
	}
	return &sftp
}

func TestAll(t *testing.T) {
	s := newTestSFTP(t)

	tmpDir, err := ioutil.TempDir("", "sftptest")
	if err != nil {
		t.Fatalf("unable to create test dir: %v", err)
	}
	dir := filepath.Join(tmpDir, "subdir")
	testMkdir(t, s.Client, dir)
	file := filepath.Join(dir, "upload")

	testWriteRead(t, s.Client, file)
	testStat(t, s.Client, file)
	testChown(t, s.Client, file)
	// Remove the file and create a new one to test File.Chown
	// The previous file may have lost the premission to change group.
	testRemove(t, s.Client, file)
	testWriteRead(t, s.Client, file)
	testFileChown(t, s.Client, file)
	testRename(t, s.Client, file)
	testPosixRename(t, s.Client, file)
	testReaddir(t, s.Client, dir)
	testSymlink(t, s.Client, file)
	testRemove(t, s.Client, file)
	testPut(t, s.Client, file)
	testChmod(t, s.Client, file)
	testRemove(t, s.Client, file)
	testRmdir(t, s.Client, dir)
	// TODO(ekg): test that the chanList is in the right state.

	s.Close()
	s.cmd.Process.Kill()
	s.cmd.Wait()
}

func testStat(t *testing.T, s *Client, file string) {
	fi, err := s.Stat(file)
	if err != nil {
		t.Errorf("Stat(%q) = _, %v want nil", file, err)
		return
	}
	if fi.IsDir() {
		t.Errorf("fi.IsDir() = true, want false")
	}
	if fi.Mode()&os.ModePerm != 0644 {
		t.Errorf("fi.Mode() & os.ModePerm = %o, want %o", fi.Mode()&os.ModePerm, 0644)
	}
	if fi.Name() != file {
		t.Errorf("fi.Name() = %q, want %q", fi.Name(), file)
	}
}

func testWriteRead(t *testing.T, s *Client, file string) {
	f, err := s.OpenFile(file, int(os.O_WRONLY|os.O_CREATE|os.O_TRUNC), 0644)
	if err != nil {
		t.Errorf("Open(%q, WRONLY|CREATE|TRUNC, nil) = _, %v, want non-nil", file, err)
		return
	}
	data := []byte("test")
	for i := 0; i < 2; i++ {
		if n, err := f.Write(data); err != nil || n != len(data) {
			t.Errorf("Write(%q) = %d, %v, want %d, nil", data, n, err, len(data))
		}
	}
	if err := f.Close(); err != nil {
		t.Errorf("f.Close() = %v, want nil", err)
	}

	f, err = s.OpenFile(file, int(os.O_RDONLY), 0)
	if err != nil {
		t.Errorf("Open(%q, RDONLY, nil) = _, %v, want non-nil", file, err)
		return
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		t.Errorf("ReadAll(%v) = _, %v, want nil", f, b)
		return
	}
	if len(b) != 2*len(data) {
		t.Errorf("length read = %d, want %d", len(b), 2*len(data))
		return
	}
	if string(b) != string(data)+string(data) {
		t.Errorf("Read %q, want %q", string(b), string(data)+string(data))
	}
	if err := f.Close(); err != nil {
		t.Errorf("f.Close() = %v, want nil", err)
	}

	f, err = s.OpenFile(file, int(os.O_RDWR|os.O_APPEND), 0)
	if err != nil {
		t.Errorf("Open(%q, RDONLY, nil) = _, %v, want non-nil", file, err)
		return
	}
	if n, err := f.Write([]byte("a")); err != nil || n != 1 {
		t.Errorf("Write('a') = %d, %v, want 1, nil", n, err)
		return
	}
	if r, err := f.Seek(1, 0); err != nil || r != 1 {
		t.Errorf("Seek(1, 0) = %d, %v, want 1, nil", r, err)
	}
	buf := make([]byte, 1)
	if n, err := f.Read(buf); err != nil || n != 1 {
		t.Errorf("Read(...) = %d, %v, want 1, nil", n, err)
	}
	if string(buf) != "e" {
		t.Errorf("string(%q) != %q", buf, "e")
	}
}

func testChown(t *testing.T, s *Client, path string) {
	uid, oldGID, err := stat(path)
	if err != nil {
		t.Errorf("stat(%q) = _, %v want nil", path, err)
		return
	}

	groups, err := os.Getgroups()
	if err != nil {
		t.Errorf("os.GetGroups() = _, %v, want nil", err)
		return
	}
	var newGID int
	if groups[0] != int(oldGID) {
		newGID = groups[0]
	} else {
		newGID = groups[1]
	}

	if err := s.Chown(path, int(uid), newGID); err != nil {
		t.Errorf("Chown(%q, %d, %d) = %v, want nil", path, uid, newGID, err)
	}

	_, gid, err := stat(path)
	if err != nil {
		t.Errorf("stat(%q) = _, %v want nil", path, err)
	}
	if gid != uint32(newGID) {
		t.Errorf("gid = %d, want %d", gid, newGID)
	}
}

func testFileChown(t *testing.T, s *Client, path string) {
	uid, oldGID, err := stat(path)
	if err != nil {
		t.Errorf("stat(%q) = _, %v want nil", path, err)
		return
	}

	groups, err := os.Getgroups()
	if err != nil {
		t.Errorf("os.GetGroups() = _, %v, want nil", err)
		return
	}
	var newGID int
	if groups[0] != int(oldGID) {
		newGID = groups[0]
	} else {
		newGID = groups[1]
	}

	f, err := s.Open(path)
	if err != nil {
		t.Errorf("Open(%q) = %v, want nil", path, err)
	}
	f.Chown(int(uid), newGID)

	_, gid, err := stat(path)
	if err != nil {
		t.Errorf("stat(%q) = _, %v want nil", path, err)
	}
	if gid != uint32(newGID) {
		t.Errorf("gid = %d, want %d", gid, newGID)
	}
}

func stat(path string) (uid, gid uint32, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	uid = fi.Sys().(*syscall.Stat_t).Uid
	gid = fi.Sys().(*syscall.Stat_t).Gid
	return
}

func testRename(t *testing.T, s *Client, path string) {
	newPath := path + ".new"
	if err := s.Rename(path, newPath); err != nil {
		t.Errorf("s.Rename(%q, %q) = %v, want nil", path, newPath, err)
		return
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Errorf("os.Stat(%q) = _, %v, want nil", newPath, err)
		return
	}
	if err := s.Rename(newPath, path); err != nil {
		t.Errorf("s.Rename(%q, %q) = %v, want nil", newPath, path, err)
		return
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("os.Stat(%q) = _, %v, want nil", path, err)
		return
	}
}

func testPosixRename(t *testing.T, s *Client, path string) {
	newPath := path + ".new"
	if err := s.PosixRename(path, newPath); err != nil {
		t.Errorf("s.PosixRename(%q, %q) = %v, want nil", path, newPath, err)
		return
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Errorf("os.Stat(%q) = _, %v, want nil", newPath, err)
		return
	}
	if err := s.PosixRename(newPath, path); err != nil {
		t.Errorf("s.PosixRename(%q, %q) = %v, want nil", newPath, path, err)
		return
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("os.Stat(%q) = _, %v, want nil", path, err)
		return
	}
}

func testRemove(t *testing.T, s *Client, path string) {
	if err := s.Remove(path); err != nil {
		t.Errorf("s.Remove(%q) = %v, want nil", path, err)
		return
	}
	if _, err := os.Stat(path); err == nil {
		t.Errorf("os.Stat(%q) = _, nil, want non-nil", path)
	}
}

func testMkdir(t *testing.T, s *Client, path string) {
	if err := s.Mkdir(path, 0775); err != nil {
		t.Fatalf("s.Mkdir(%qi, 0755) = %v, want nil", path, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) = _, %v want nil", path, err)
	}
	if !fi.IsDir() {
		t.Fatalf("fi.IsDir() = false, want true")
	}
	if fi.Mode()&os.ModePerm != os.FileMode(0775) {
		t.Errorf("fi.Mode() = %o, want %o", fi.Mode()&os.ModePerm, os.FileMode(0775))
	}
}

func testRmdir(t *testing.T, s *Client, path string) {
	if err := s.Rmdir(path); err != nil {
		t.Errorf("s.Rmdir(%q) = %v, want nil", path, err)
		return
	}
	if _, err := os.Stat(path); err == nil {
		t.Errorf("os.Stat(%q) = _, nil, want non-nil", path)
	}
}

func testReaddir(t *testing.T, s *Client, path string) {
	names, err := s.ReadDir(path)
	if err != nil {
		t.Errorf("s.ReadDir(%q) = _, %v, want nil", path, err)
	}
	found := map[string]bool{
		".":      false,
		"..":     false,
		"upload": false,
	}
	for _, n := range names {
		if _, ok := found[n.Name()]; ok {
			found[n.Name()] = true

		if n.Name() == "." && !n.IsDir() {
		  t.Errorf("ReadDir(%q) claims '.' is not a directory, mode %v", path, n.Mode())
		}
			continue
		}
		t.Errorf("s.ReadDir(%q) returned unexpected name %q", path, n.Name())
	}
	for k, v := range found {
		if !v {
			t.Errorf("s.ReadDir(%q) did not return expected name %q", path, k)
		}
	}
}

func testSymlink(t *testing.T, s *Client, path string) {
	linkPath := path + ".link"
	if err := s.Symlink(path, linkPath); err != nil {
		t.Errorf("s.Symlink(%q, %q) = %v, want nil", path, linkPath, err)
		return
	}
	linkFi, err := s.LStat(linkPath)
	if err != nil {
		t.Errorf("s.LStat(%q) = _, %v, want nil", linkPath, err)
	}
	pathFi, err := s.Stat(path)
	if err != nil {
		t.Errorf("s.Stat(%q) = _, %v, want nil", path, err)
	}
	if os.SameFile(linkFi, pathFi) {
		t.Errorf("os.SameFile(%q, %q) = true, want false", linkPath, path)
	}
	if err := s.Remove(linkPath); err != nil {
		t.Errorf("s.Remove(%q) = %v want nil", linkPath, err)
	}
}

func testPut(t *testing.T, s *Client, file string) {
	b := []byte("test pattern")
	if n, err := s.Put(bytes.NewReader(b), file); err != nil || int(n) != len(b) {
		t.Errorf("Put(%q, %q) = %v, %v, want %d, nil", b, file, n, err, len(b))
	}
	f, err := s.OpenFile(file, int(os.O_RDONLY), 0)
	if err != nil {
		t.Errorf("Open(%q, RDONLY, nil) = _, %v, want non-nil", file, err)
		return
	}
	defer f.Close()
	b2, err := ioutil.ReadAll(f)
	if err != nil {
		t.Errorf("ReadAll(%v) = _, %v, want nil", f, b)
		return
	}
	if string(b) != string(b2) {
		t.Errorf("Put wrote %q but subsequent read returned %q", b, b2)
	}
}

func testChmod(t *testing.T, s *Client, file string) {
	m := os.FileMode(0757)
	if err := s.Chmod(file, m); err != nil {
		t.Errorf("Chown(%q, %v) = %v, want nil", file, m, err)
		return
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Errorf("os.Stat(%q) = _, %v want nil", file, err)
		return
	}
	if fi.Mode()&os.ModePerm != m {
		t.Errorf("fi.Mode() = %o, want %o", fi.Mode()&os.ModePerm, m)
	}
}
