// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package sftp

import (
	"encoding/binary"
	"os"
	"time"

	"code.google.com/p/gosshnew/ssh"
)

// Constants used for indicating which fields are present in the returned data.
const (
	fxpAttrSize        = 1
	fxpAttrUIDGID      = 2
	fxpAttrPermissions = 4
	fxpAttrACModTime   = 8
	fxpAttrExtended    = 0x80000000
)

// FileAttributes contains information about a particular file. It fulfills the
// os.FileInfo interface. However, the SFTP specification allows the server to
// only conditionally include fields if the server supports them. See the
// function documentation for how this is handled.
type FileAttributes struct {
	name       string
	flags      uint32
	size       uint64
	uid        uint32
	gid        uint32
	permission uint32
	aTime      uint32
	mTime      uint32
	ext        []extInfo
}

type extInfo struct {
	Type string
	Data string
	Rest []byte `ssh:"rest"`
}

// newFileAttributes returns a new FileAttributes that represents the passed
// data.
func newFileAttributes(data []byte) (_ *FileAttributes, out []byte, err error) {
	// TODO(ekg): add error len(data) doesn't have enough bytes.
	f := &FileAttributes{
		flags: binary.BigEndian.Uint32(data[0:4]),
	}
	data = data[4:]
	if f.flags&fxpAttrSize > 0 {
		f.size = binary.BigEndian.Uint64(data[0:8])
		data = data[8:]
	}
	if f.flags&fxpAttrUIDGID > 0 {
		f.uid = binary.BigEndian.Uint32(data[0:4])
		f.gid = binary.BigEndian.Uint32(data[4:8])
		data = data[8:]
	}
	if f.flags&fxpAttrPermissions > 0 {
		f.permission = binary.BigEndian.Uint32(data[0:4])
		data = data[4:]
	}
	if f.flags&fxpAttrACModTime > 0 {
		f.aTime = binary.BigEndian.Uint32(data[0:4])
		f.mTime = binary.BigEndian.Uint32(data[4:8])
		data = data[8:]
	}
	if f.flags&fxpAttrExtended > 0 {
		c := binary.BigEndian.Uint32(data[0:4])
		data = data[4:]
		for i := 0; i < int(c); i++ {
			e := extInfo{}
			if err = ssh.Unmarshal(data, &e); err != nil {
				return
			}
			data = e.Rest
			e.Rest = nil
			f.ext = append(f.ext, e)
		}
	}
	return f, data, nil
}

// Name returns the name of the file to which the data applies.
func (f FileAttributes) Name() string {
	return f.name
}

// Size returns the size in bytes of the file. If the size was not returned by
// the server, -1 is returned.
func (f FileAttributes) Size() int64 {
	if f.flags&fxpAttrSize == 0 {
		return -1
	}
	// TODO(ekg): this conversion might overflow.
	return int64(f.size)
}

// bytes returns the byte representation of the struct instance for shipping to
// the server.
func (f *FileAttributes) bytes() []byte {
	b := make([]byte, 4, 36)
	binary.BigEndian.PutUint32(b[0:4], f.flags)
	d := make([]byte, 4)
	if f.flags&fxpAttrUIDGID > 0 {
		binary.BigEndian.PutUint32(d, f.uid)
		b = append(b, d...)
		binary.BigEndian.PutUint32(d, f.gid)
		b = append(b, d...)
	}
	if f.flags&fxpAttrPermissions > 0 {
		binary.BigEndian.PutUint32(d, f.permission)
		b = append(b, d...)
	}
	if f.flags&fxpAttrACModTime > 0 {
		binary.BigEndian.PutUint32(d, f.aTime)
		b = append(b, d...)
		binary.BigEndian.PutUint32(d, f.mTime)
		b = append(b, d...)
	}
	return b
}

// setID is a convenience function to set the UID and the GID before sending
// the byte representation to the server.
func (f *FileAttributes) setID(uid, gid uint32) {
	f.flags |= fxpAttrUIDGID
	f.uid = uid
	f.gid = gid
}

// setPermission is a convenience function to set the UID and the GID before
// sending the byte representation to the server.
func (f *FileAttributes) setPermission(perms uint32) {
	f.flags |= fxpAttrPermissions
	f.permission = perms
}

// Mode returns a file's mode and permission bits. If mode was not returned by
// the server, this method returns 0.
func (f FileAttributes) Mode() os.FileMode {
	if f.flags&fxpAttrPermissions == 0 {
		return 0
	}
	return os.FileMode(f.permission)
}

// ModTime returns the modification time of the file. If the time was not
// returned by the server, this method returns the zero-time.
func (f FileAttributes) ModTime() time.Time {
	if f.flags&fxpAttrACModTime == 0 {
		return time.Time{}
	}
	return time.Unix(int64(f.mTime), 0)
}

// IsDir returns true if the entity is a directory. If mode was not returned by
// the server, this method's return value is undefined.
func (f FileAttributes) IsDir() bool {
	return f.Mode().IsDir()
}

// Sys returns the underlying data source of this structure.
func (f FileAttributes) Sys() interface{} {
	return f
}
