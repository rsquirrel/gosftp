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
	// GetID returns the identifier of the instance.
	GetID() uint32
	// SetID sets the identifier of the instance.
	SetID(uint32)
}

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
	// Ext may contain a list of strings representing optional extensions.
	Ext []byte `ssh:"rest"`
}

// Apologies for the repetition of GetID and SetID: they are required because
// the ssh.Marshal routine can't handle pointers to ints. If it could, we could
// use a new embedded type instead of "ID uint32". Alternatively, we could
// duplicate *even more* code in client.go.

type fxpOpenMsg struct {
	ID       uint32 `sshtype:"3"`
	Filename string
	Pflags   uint32
	AttrData []byte `ssh:"rest"`
}

func (f *fxpOpenMsg) GetID() uint32   { return f.ID }
func (f *fxpOpenMsg) SetID(id uint32) { f.ID = id }

type fxpCloseMsg struct {
	ID     uint32 `sshtype:"4"`
	Handle string
}

func (f *fxpCloseMsg) GetID() uint32   { return f.ID }
func (f *fxpCloseMsg) SetID(id uint32) { f.ID = id }

type fxpReadMsg struct {
	ID     uint32 `sshtype:"5"`
	Handle string
	Offset uint64
	Length uint32
}

func (f *fxpReadMsg) GetID() uint32   { return f.ID }
func (f *fxpReadMsg) SetID(id uint32) { f.ID = id }

type fxpWriteMsg struct {
	ID     uint32 `sshtype:"6"`
	Handle string
	Offset uint64
	Data   []byte
}

func (f *fxpWriteMsg) GetID() uint32   { return f.ID }
func (f *fxpWriteMsg) SetID(id uint32) { f.ID = id }

type fxpRemoveMsg struct {
	ID       uint32 `sshtype:"13"`
	Filename string
}

func (f *fxpRemoveMsg) GetID() uint32   { return f.ID }
func (f *fxpRemoveMsg) SetID(id uint32) { f.ID = id }

type fxpRenameMsg struct {
	ID      uint32 `sshtype:"18"`
	OldPath string
	NewPath string
}

func (f *fxpRenameMsg) GetID() uint32   { return f.ID }
func (f *fxpRenameMsg) SetID(id uint32) { f.ID = id }

type fxpMkdirMsg struct {
	ID       uint32 `sshtype:"14"`
	Path     string
	AttrData []byte `ssh:"rest"`
}

func (f *fxpMkdirMsg) GetID() uint32   { return f.ID }
func (f *fxpMkdirMsg) SetID(id uint32) { f.ID = id }

type fxpRmdirMsg struct {
	ID   uint32 `sshtype:"15"`
	Path string
}

func (f *fxpRmdirMsg) GetID() uint32   { return f.ID }
func (f *fxpRmdirMsg) SetID(id uint32) { f.ID = id }

type fxpOpenDirMsg struct {
	ID   uint32 `sshtype:"11"`
	Path string
}

func (f *fxpOpenDirMsg) GetID() uint32   { return f.ID }
func (f *fxpOpenDirMsg) SetID(id uint32) { f.ID = id }

type fxpReadDirMsg struct {
	ID     uint32 `sshtype:"12"`
	Handle string
}

func (f *fxpReadDirMsg) GetID() uint32   { return f.ID }
func (f *fxpReadDirMsg) SetID(id uint32) { f.ID = id }

type fxpStatMsg struct {
	ID   uint32 `sshtype:"17"`
	Path string
}

func (f *fxpStatMsg) GetID() uint32   { return f.ID }
func (f *fxpStatMsg) SetID(id uint32) { f.ID = id }

type fxpLStatMsg struct {
	ID   uint32 `sshtype:"7"`
	Path string
}

func (f *fxpLStatMsg) GetID() uint32   { return f.ID }
func (f *fxpLStatMsg) SetID(id uint32) { f.ID = id }

type fxpFStatMsg struct {
	ID     uint32 `sshtype:"8"`
	Handle string
}

func (f *fxpFStatMsg) GetID() uint32   { return f.ID }
func (f *fxpFStatMsg) SetID(id uint32) { f.ID = id }

type fxpSetStatMsg struct {
	ID       uint32 `sshtype:"9"`
	Path     string
	AttrData []byte `ssh:"rest"`
}

func (f *fxpSetStatMsg) GetID() uint32   { return f.ID }
func (f *fxpSetStatMsg) SetID(id uint32) { f.ID = id }

type fxpFSetStatMsg struct {
	ID       uint32 `sshtype:"10"`
	Handle   string
	AttrData []byte `ssh:"rest"`
}

func (f *fxpFSetStatMsg) GetID() uint32   { return f.ID }
func (f *fxpFSetStatMsg) SetID(id uint32) { f.ID = id }

type fxpReadLinkMsg struct {
	ID   uint32 `sshtype:"19"`
	Path string
}

func (f *fxpReadLinkMsg) GetID() uint32   { return f.ID }
func (f *fxpReadLinkMsg) SetID(id uint32) { f.ID = id }

type fxpRealPathMsg struct {
	ID   uint32 `sshtype:"16"`
	Path string
}

func (f *fxpRealPathMsg) GetID() uint32   { return f.ID }
func (f *fxpRealPathMsg) SetID(id uint32) { f.ID = id }

type fxpSymlinkMsg struct {
	ID         uint32 `sshtype:"20"`
	LinkPath   string
	TargetPath string
}

func (f *fxpSymlinkMsg) GetID() uint32   { return f.ID }
func (f *fxpSymlinkMsg) SetID(id uint32) { f.ID = id }

type posixRenameMsg struct {
	ID        uint32 `sshtype:"200"`
	Extension string
	OldPath   string
	NewPath   string
}

func (f *posixRenameMsg) GetID() uint32   { return f.ID }
func (f *posixRenameMsg) SetID(id uint32) { f.ID = id }

// Status is a error number defined by section 7, "Responses from the Server to
// the Client".
type Status uint32

// The list of error codes defined by the protocol.
const (
	OK Status = iota
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
	ID       uint32 `sshtype:"101"`
	Status   Status
	Msg      string
	Language string
}

func (f *fxpStatusResp) GetID() uint32   { return f.ID }
func (f *fxpStatusResp) SetID(id uint32) { f.ID = id }

func (f fxpStatusResp) Error() string {
	return fmt.Sprintf("sftp: %s", f.Msg)
}

type fxpHandleResp struct {
	ID     uint32 `sshtype:"102"`
	Handle string
}

func (f *fxpHandleResp) GetID() uint32   { return f.ID }
func (f *fxpHandleResp) SetID(id uint32) { f.ID = id }

type fxpDataResp struct {
	ID   uint32 `sshtype:"103"`
	Data []byte
}

func (f *fxpDataResp) GetID() uint32   { return f.ID }
func (f *fxpDataResp) SetID(id uint32) { f.ID = id }

type fxpNameData struct {
	Filename string
	Longname string
	Data     []byte `ssh:"rest"`
}

type fxpNameResp struct {
	ID    uint32 `sshtype:"104"`
	Count uint32
	Data  []byte `ssh:"rest"`
}

func (f *fxpNameResp) GetID() uint32   { return f.ID }
func (f *fxpNameResp) SetID(id uint32) { f.ID = id }

type nameData struct {
	filename string
	longname string
	attr     *FileAttributes
}

// Names extracts the repeated name data from the Data buffer. This message
// structure is not supported by Unmarshal, so we take advantage of the "rest"
// field.
func (r *fxpNameResp) names() ([]nameData, error) {
	if r.Count == 0 {
		return nil, nil
	}
	data := r.Data
	r.Data = nil
	names := make([]nameData, 0, r.Count)
	for len(data) > 0 {
		name := fxpNameData{}
		if err := ssh.Unmarshal(data, &name); err != nil {
			return nil, err
		}
		data = name.Data
		var attr *FileAttributes
		var err error
		attr, data, err = newFileAttributes(data)
		if err != nil {
			return nil, err
		}
		names = append(names, nameData{
			filename: name.Filename,
			longname: name.Longname,
			attr:     attr,
		})
	}
	if len(data) != 0 {
		return nil, fmt.Errorf("Expected to have 0 bytes of data left, have %d", len(data))
	}

	return names, nil
}

type fxpAttrsResp struct {
	ID       uint32 `sshtype:"105"`
	AttrData []byte `ssh:"rest"`
}

func (f *fxpAttrsResp) GetID() uint32   { return f.ID }
func (f *fxpAttrsResp) SetID(id uint32) { f.ID = id }

type fxpExtendedResp struct {
	ID   uint32 `sshtype:"201"`
	Data []byte `ssh:"rest"`
}

func (f *fxpExtendedResp) GetID() uint32   { return f.ID }
func (f *fxpExtendedResp) SetID(id uint32) { f.ID = id }

// UnexpectedMessageError results when the SSH message that was received did
// not match what the protocol specifies as the proper returned message type.
type UnexpectedMessageError struct {
	expected, got uint8
}

func (u UnexpectedMessageError) Error() string {
	return fmt.Sprintf("ssh: unexpected message type %d (expected %d)", u.got, u.expected)
}

// GetStatus retrieves the sftp status code inside the sftp error. The second
// returned value will be false if the given error is not an sftp error.
func GetStatus(err error) (Status, bool) {
	resp, ok := err.(*fxpStatusResp)
	if !ok {
		return 0, ok
	}
	return resp.Status, true
}
