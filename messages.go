// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package sftp

import (
	"fmt"

	"code.google.com/p/gosshnew/ssh"
)

// SSH file transer protocol request packet types, defined in section 3,
// "General Packet Format".
const (
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

// SSH file transer protocol response packet types, defined in section 3,
// "General Packet Format".
const (
	fxpPacketStatus = iota + 101
	fxpPacketHandle
	fxpPacketData
	fxpPacketName
	fxpPacketAttrs
)

// SSH file transfer protocol message types to support vendor-specific
// extentions.
const (
	fxpPacketExtended      = 200
	fxpPacketExtendedReply = 201
)

// ider specifies functions for a struct to contain an identifier.
type ider interface {
	// ID returns the identifier of the instance.
	ID() uint32
	// SetID sets the identifier of the instance.
	SetID(uint32)
}

// ReqID is a request ID used in all requests. It has external visibility for
// unmarshalling purposes.
type ReqID uint32

func (f ReqID) ID() uint32 {
	return uint32(f)
}
func (f ReqID) SetID(id uint32) { f = ReqID(id) }

// fxpInitMsg is the first message sent from client to server in the SFTP
// protocol.
type fxpInitMsg struct {
	// Version specifies the highest version number of the protocol
	// implemented.
	Version uint32 `sshtype:"1"`
}

// fxpVersionMsg is the response to an fxpInitMsg.
type fxpVersionMsg struct {
	// Version contains the lowest of the server's and client's implemented
	// version.
	Version uint32 `sshtype:"2"`
	// Data may contain a list of strings representing optional extensions.
	// No extensions are presently supported.
	Data []byte `ssh:"rest"`
}

// stringList parses a series of string fields from a byte buffer.
func stringList(buf []byte) []string {
	return nil
}

type fxpOpenMsg struct {
	ReqID    `sshtype:"3"`
	Filename string
	Pflags   uint32
	AttrData []byte `ssh:"rest"`
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
	ReqID    `sshtype:"14"`
	Path     string
	AttrData []byte `ssh:"rest"`
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

type fxpLStatMsg struct {
	ReqID `sshtype:"7"`
	Path  string
}

type fxpFStatMsg struct {
	ReqID  `sshtype:"8"`
	Handle string
}

type fxpSetStatMsg struct {
	ReqID    `sshtype:"9"`
	Path     string
	AttrData []byte `ssh:"rest"`
}

type fxpFSetStatMsg struct {
	ReqID    `sshtype:"10"`
	Handle   string
	AttrData []byte `ssh:"rest"`
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

// fxpExtendedMsg is the request type for vendor-specific extensions
// implemented by the server.
type fxpExtendedMsg struct {
	ReqID `sshtype:"200"`
	// Extension is the extension name, in the form "name@domain".
	Extension string
	// Data is the payload for the extension, which may be empty.
	Data []byte
}

// Status is a error number defined by section 7, "Responses from the Server to
// the Client".
type Status uint32

// The list of error codes defined by the protocol.
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
	Filename string
	Longname string
	Data     []byte `ssh:"rest"`
	attr     *FileAttributes
}

type fxpNameResp struct {
	ReqID `sshtype:"104"`
	Count uint32
	Data  []byte `ssh:"rest"`
}

func (r *fxpNameResp) Attrs() ([]fxpNameData, error) {
	if r.Count == 0 {
		return nil, nil
	}
	data := r.Data
	r.Data = nil
	names := make([]fxpNameData, 0, r.Count)
	for len(data) > 0 {
		name := fxpNameData{}
		if err := ssh.Unmarshal(data, &name); err != nil {
			return nil, err
		}
		data = name.Data
		name.Data = nil
		var err error
		name.attr, data, err = newFileAttributes(data)
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if len(data) != 0 {
		return nil, fmt.Errorf("Expected to have 0 bytes of data left, have %d", len(data))
	}

	return names, nil
}

type fxpAttrsResp struct {
	ReqID    `sshtype:"105"`
	AttrData []byte `ssh:"rest"`
}

type fxpExtendedResp struct {
	ReqID `sshtype:"201"`
	Data  []byte `ssh:"rest"`
}

// UnexpectedMessageError results when the SSH message that was received did
// not match what the protocol specifies as the proper returned message type.
type UnexpectedMessageError struct {
	expected, got uint8
}

func (u UnexpectedMessageError) Error() string {
	return fmt.Sprintf("ssh: unexpected message type %d (expected %d)", u.got, u.expected)
}
