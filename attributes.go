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
)

const (
	fxpAttrSize        = 1
	fxpAttrUIDGID      = 2
	fxpAttrPermissions = 4
	fxpAttrACModTime   = 8
	fxpAttrExtended    = 0x80000000
)

type FileAttributes struct {
	name       string
	flags      uint32
	size       uint64 // 0-7
	uid        uint32 // 8-11
	gid        uint32 // 12-15
	permission uint32 // 16-19
	aTime      uint32 // 20-23
	mTime      uint32 // 24-27
	data       []byte
	// TODO(ekg): support extended data. extendedCount *uint32 // 28-31
}

func NewFileAttributes(data []byte) *FileAttributes {
	// TODO(ekg): add error if len(data) < 4
	f := &FileAttributes{
		data: data[4:],
	}
	f.flags = binary.BigEndian.Uint32(data[0:4])
	return f
}

func (f FileAttributes) Name() string {
	return f.name
}

// TODO(ekg): figure out what to do if these aren't present in the data.
func (f FileAttributes) Size() int64 {
	if f.flags&fxpAttrSize == 0 {
		return -1
	}
	return int64(binary.BigEndian.Uint64(f.data[0:8]))
}

func (f *FileAttributes) bytes() []byte {
	b := make([]byte, 0, 36)
	d := make([]byte, 4)
	binary.BigEndian.PutUint32(d, f.flags)
	b = append(b, d...)
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

func (f *FileAttributes) setID(uid, gid uint32) {
	f.flags |= fxpAttrUIDGID
	f.uid = uid
	f.gid = gid
}

func (f *FileAttributes) setPermission(perms uint32) {
	f.flags |= fxpAttrPermissions
	f.permission = perms
}

func (f FileAttributes) Mode() os.FileMode {
	if f.flags&fxpAttrPermissions == 0 {
		return 0
	}
	// TODO(ekg): explicitly convert this.
	return os.FileMode(binary.BigEndian.Uint32(f.data[16:20]))
}

func (f FileAttributes) ModTime() time.Time {
	if f.flags&fxpAttrACModTime == 0 {
		return time.Unix(0, 0)
	}
	t := binary.BigEndian.Uint32(f.data[24:28])
	return time.Unix(int64(t), 0)
}

func (f FileAttributes) IsDir() bool {
	return f.Mode().IsDir()
}

func (f FileAttributes) Sys() interface{} {
	return f
}
