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
	Flags      uint32
	size       uint64 // 0-7
	uid        uint32 // 8-11
	gid        uint32 // 12-15
	permission uint32 // 16-19
	aTime      uint32 // 20-23
	mTime      uint32 // 24-27
	Data       []byte `ssh:"rest"`

	// TODO(ekg): support extended data. extendedCount *uint32 // 28-31
}

func (f FileAttributes) Name() string {
	return f.name
}

// TODO(ekg): figure out what to do if these aren't present in the data.
func (f FileAttributes) Size() int64 {
	if f.Flags&fxpAttrSize == 0 {
		return -1
	}
	return int64(binary.BigEndian.Uint64(f.Data[0:8]))
}

// TODO(ekg): fill in the rest
func (f *FileAttributes) regen() {
	f.Data = make([]byte, 0, 32)
	if f.Flags&fxpAttrUIDGID > 0 {
		d := make([]byte, 4)
		binary.BigEndian.PutUint32(d, f.uid)
		f.Data = append(f.Data, d...)
		binary.BigEndian.PutUint32(d, f.gid)
		f.Data = append(f.Data, d...)
	}
	if f.Flags&fxpAttrPermissions > 0 {
		d := make([]byte, 4)
		binary.BigEndian.PutUint32(d, f.permission)
		f.Data = append(f.Data, d...)
	}
	if f.Flags&fxpAttrACModTime > 0 {
		d := make([]byte, 4)
		binary.BigEndian.PutUint32(d, f.aTime)
		f.Data = append(f.Data, d...)
		binary.BigEndian.PutUint32(d, f.mTime)
		f.Data = append(f.Data, d...)
	}
}

func (f *FileAttributes) setID(uid, gid uint32) {
	f.Flags |= fxpAttrUIDGID
	f.uid = uid
	f.gid = gid
	f.regen()
}

func (f *FileAttributes) setPermission(perms uint32) {
	f.Flags |= fxpAttrPermissions
	f.permission = perms
	f.regen()
}

func (f FileAttributes) Mode() os.FileMode {
	if f.Flags&fxpAttrPermissions == 0 {
		return 0
	}
	// TODO(ekg): explicitly convert this.
	return os.FileMode(binary.BigEndian.Uint32(f.Data[16:20]))
}

func (f FileAttributes) ModTime() time.Time {
	if f.Flags&fxpAttrACModTime == 0 {
		return time.Unix(0, 0)
	}
	t := binary.BigEndian.Uint32(f.Data[24:28])
	return time.Unix(int64(t), 0)
}

func (f FileAttributes) IsDir() bool {
	return f.Mode().IsDir()
}

func (f FileAttributes) Sys() interface{} {
	return f
}
