// Copyright 2014 Google Inc. All rights reserved.
// 
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package sftp

import (
	"fmt"
)

const (
	// These are SSH file transer protocol (Client) packet types, as defined in section 3...  const (
	fxpPacketInit = iota + 1
	fxpPacketVersion
	fxpPacketOpen
	fxpPacketClose
	fxpPacketRead
	fxpPacketWrite
	fxpPacketLStat
	fxpPacketFStat
	fxpPacketSetStat
	fxpPacketFSetStat
	fxpPacketOpenDir
	fxpPacketReadDir
	fxpPacketRemove
	fxpPacketMkDir
	fxpPacketRmDir
	fxpPacketRealPath
	fxpPacketStat
	fxpPacketRename
	fxpPacketReadLink
	fxpPacketSymLink
)

const (
	fxpPacketStatus = iota + 101
	fxpPacketHandle
	fxpPacketData
	fxpPacketName
	fxpPacketAttrs
	fxpPacketExtended
	fxpPacketExtendedReply
)

type ider interface {
	ID() uint32
	SetID(uint32)
}

type ReqID uint32

func (f ReqID) ID() uint32 {
	return uint32(f)
}
func (f ReqID) SetID(id uint32) { f = ReqID(id) }

type fxpInitMsg struct {
	Version uint32 `sshtype:"1"`
}

type fxpVersionMsg struct {
	Version uint32 `sshtype:"2"`
	Data    []byte `ssh:"rest"`
}

type fxpOpenMsg struct {
	ReqID    `sshtype:"3"`
	Filename string
	Pflags   uint32
	Attrs    FileAttributes
}

type fxpCloseMsg struct {
	ReqID  `sshtype:"4"`
	Handle string
}

type fxpReadMsg struct {
	ReqID  `sshtype:"5"`
	Handle string
	Offset uint64
	Length uint32
}

type fxpWriteMsg struct {
	ReqID  `sshtype:"6"`
	Handle string
	Offset uint64
	Data   []byte
}

type fxpRemoveMsg struct {
	ReqID    `sshtype:"13"`
	Filename string
}

type fxpRenameMsg struct {
	ReqID   `sshtype:"18"`
	OldPath string
	NewPath string
}

type fxpMkdirMsg struct {
	ReqID `sshtype:"14"`
	Path  string
	Attrs FileAttributes
}

type fxpRmdirMsg struct {
	ReqID `sshtype:"15"`
	Path  string
}

type fxpOpenDirMsg struct {
	ReqID `sshtype:"11"`
	Path  string
}

type fxpReadDirMsg struct {
	ReqID  `sshtype:"12"`
	Handle string
}

type fxpStatMsg struct {
	ReqID `sshtype:"17"`
	Path  string
}

type fxpFStatMsg struct {
	ReqID  `sshtype:"8"`
	Handle string
}

type fxpSetStatMsg struct {
	ReqID `sshtype:"9"`
	Path  string
	Attrs FileAttributes
}

type fxpFSetStatMsg struct {
	ReqID  `sshtype:"10"`
	Handle string
	Attrs  FileAttributes
}

type fxpReadLinkMsg struct {
	ReqID `sshtype:"19"`
	Path  string
}

type fxpRealPathMsg struct {
	ReqID `sshtype:"16"`
	Path  string
}

type fxpSymlinkMsg struct {
	ReqID      `sshtype:"20"`
	LinkPath   string
	TargetPath string
}

//////////////////////////////

type Status uint32

const (
	ok Status = iota
	eof
	NoSuchFile
	PermissionDenied
	Failure
	BadMessage
	NoConnection
	ConnectionLost
	OpUnsupported
)

type fxpStatusResp struct {
	ReqID    `sshtype:"101"`
	Status   Status
	Msg      string
	Language string
}

func (f fxpStatusResp) Error() string {
	return fmt.Sprintf("sftp: %s", f.Msg)
}

type fxpHandleResp struct {
	ReqID  `sshtype:"102"`
	Handle string
}

type fxpDataResp struct {
	ReqID `sshtype:"103"`
	Data  []byte
}

type fxpNameData struct {
	ReqID
	Filename string
	Longname string
	Attrs    FileAttributes
}

type fxpNameResp struct {
	ReqID `sshtype:"104"`
	Data  []fxpNameData
}

type fxpAttrsResp struct {
	ReqID `sshtype:"105"`
	Attrs FileAttributes
}

type fxpExtendedResp struct {
	ReqID `sshtype:"201"`
	Data  []byte `ssh:"rest"`
}

// UnexpectedMessageError results when the SSH message that we received didn't
// match what we wanted.
type UnexpectedMessageError struct {
	expected, got uint8
}

func (u UnexpectedMessageError) Error() string {
	return fmt.Sprintf("ssh: unexpected message type %d (expected %d)", u.got, u.expected)
}
