// Copyright 2014 Google Inc. All rights reserved.
// 
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package sftp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"code.google.com/p/gosshnew/ssh"
)

// fxpChan is a channel on which a message recipient can wait for the message
// to be returned.
type fxpChan struct {
	ReqID
	c chan interface{}
	l *fxpChanList
}

// waitForResponse blocks until a message is received and returns it.
func (c *fxpChan) waitForResponse() interface{} {
	return <-c.c
}

// close removes the channel from the channel list. The receiver of messages is
// responsible for calling this method.
func (c *fxpChan) close() {
  c.l.remove(c.ReqID)
}

// fxpChanList is a list of channels that are awaiting messages.
type fxpChanList struct {
	sync.Mutex
	chans []*fxpChan
}

// newChan allocates a new channel for receiving a message.
func (l *fxpChanList) newChan() (*fxpChan, error) {
	l.Lock()
	defer l.Unlock()

	// find the lowest unused request ID in the list. Create a new channel
	// if an empty slot is found.
	for i := range l.chans {
		if l.chans[i] == nil {
		  ch := &fxpChan{ReqID: ReqID(i), c: make(chan interface{}), l: l}
			l.chans[i] = ch
			return ch, nil
		}
	}

	// The SFTP protocol defines the request identifier to be a uint32. If
	// there are no available identifiers, return an error.
	if len(l.chans) > 1<<32 {
		return nil, fmt.Errorf("no available identifiers")
	}

	// Otherwise, allocate a new channel that has the maximal request ID so
	// far.
	ch := &fxpChan{ReqID: ReqID(len(l.chans)), c: make(chan interface{}), l: l}
	l.chans = append(l.chans, ch)
	return ch, nil
}

// dispatch routes a received message to the correct channel.
func (l *fxpChanList) dispatch(id uint32, msg interface{}) {
	l.Lock()
	defer l.Unlock()
	if int(id) >= len(l.chans) {
		return
	}
	if ch := l.chans[id]; ch != nil {
		ch.c <- msg
	}
}

// remove removes a channel from the list.
func (l *fxpChanList) remove(id ReqID) {
	l.Lock()
	defer l.Unlock()
	if int(id) >= len(l.chans) {
		return
	}
	if ch := l.chans[id]; ch != nil {
		l.chans[id] = nil
		close(ch.c)
	}
}

// closeAll closes all channels.
func (l *fxpChanList) closeAll() {
	l.Lock()
	defer l.Unlock()
	for _, ch := range l.chans {
		if ch == nil {
			continue
		}
		close(ch.c)
	}
}

// Client provides an SFTP client instance.
type Client struct {
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
	chans   *fxpChanList
	session *ssh.Session
}

// NewClient creates a new SFTP client on top of an already created
// ssh.Session.
func NewClient(s *ssh.Session) (*Client, error) {
	stdin, err := s.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := s.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := s.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := s.RequestSubsystem("sftp"); err != nil {
		return nil, err
	}
	sftp := &Client{
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		chans:   &fxpChanList{},
		session: s,
	}

	if err := sftp.init(); err != nil {
		return nil, err
	}
	return sftp, nil
}

// init starts the SFTP protocol by negotiating the protocol version to use and
// starts the response handler in a goroutine.
func (s *Client) init() error {
	msg := fxpInitMsg{
		Version: 3,
	}
	if err := s.writePacket(ssh.Marshal(msg)); err != nil {
		return err
	}
	packet, err := s.readOnePacket()
	if err != nil {
		return err
	}
	resp, err := decodeClient(packet)
	if err != nil {
		return err
	}
	switch resp := resp.(type) {
	case *fxpVersionMsg:
		if resp.Version != 3 {
			return errors.New("only version 3 of Client protocol supported")
		}
	default:
		return errors.New("invalid packet received during initialization")
	}
	go s.mainLoop()

	return nil
}

// writePacket writes a packet repreesnted by a slice of bytes to the server,
// in the format specified by the protocol.
func (s *Client) writePacket(packet []byte) error {
	length := len(packet)
	lengthBytes := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}
	if _, err := s.stdin.Write(lengthBytes); err != nil {
		return err
	}
	if _, err := s.stdin.Write(packet); err != nil {
		return err
	}
	return nil
}

// readOnePacket reads a single packet sent by the server.
func (s *Client) readOnePacket() ([]byte, error) {
	// read the first four bytes that specify how long the packet is.
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(s.stdout, lengthBytes); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBytes[0:4])

	// read more bytes for the actual packet.
	packet := make([]byte, length)
	if _, err := io.ReadFull(s.stdout, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

// mainLoop reads all of the incoming packets and dispatches them to the
// channel corresponding to the returned request ID.
func (s *Client) mainLoop() {
	defer s.Close()
	for {
		packet, err := s.readOnePacket()
		if err != nil {
			if err != io.EOF {
			  fmt.Fprintf(os.Stderr, "readOnePacket: %v\n", err)
			}
			return
		}
		msg, err := decodeClient(packet)
		if err != nil {
		  fmt.Fprintf(os.Stderr, "decodeClient: %v\n", err)
			return
		}
		switch msg := msg.(type) {
		case *fxpVersionMsg, *fxpStatusResp, *fxpHandleResp, *fxpDataResp, *fxpNameResp, *fxpAttrsResp:
			s.chans.dispatch(msg.(ider).ID(), msg)
		}
	}
}

// Close closes the SSH session and stops listening for new messages. No
// further operations may be performed on the instance after calling Close.
func (s *Client) Close() {
	// session is not present in testing.
	if s.session != nil {
		s.session.Close()
	}
	s.stdin.Close()
}

// decodeClient decodes a responsee packet's raw data into its corresponding
// message structure.
func decodeClient(packet []byte) (interface{}, error) {
	var msg interface{}
	switch packet[0] {
	case fxpPacketVersion:
		msg = new(fxpVersionMsg)
	case fxpPacketStatus:
		msg = new(fxpStatusResp)
	case fxpPacketHandle:
		msg = new(fxpHandleResp)
	case fxpPacketData:
		msg = new(fxpDataResp)
	case fxpPacketName:
		msg = new(fxpNameResp)
	case fxpPacketAttrs:
		msg = new(fxpAttrsResp)
	case fxpPacketExtendedReply:
		msg = new(fxpExtendedResp)
	default:
		return nil, UnexpectedMessageError{0, packet[0]}
	}
	if err := ssh.Unmarshal(packet, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// sendRequests sends a request to the server and returns a new channel on
// which the response will be sent.
func (s *Client) sendRequest(req ider) (*fxpChan, error) {
	fxpCh, err := s.chans.newChan()
	if err != nil {
		return nil, err
	}
	req.SetID(fxpCh.ID())

	if err := s.writePacket(ssh.Marshal(req)); err != nil {
		return nil, err
	}
	return fxpCh, nil
}

// expeectAttr sends the request and returns a FileAttributes structure that is
// expected to result from the request.
func (s *Client) expectAttr(req ider) (*FileAttributes, error) {
	fxpCh, err := s.sendRequest(req)
	if err != nil {
	  return nil, err
	}
	defer fxpCh.close()
	resp := fxpCh.waitForResponse()
	switch msg := resp.(type) {
	case *fxpStatusResp:
		return nil, msg
	case *fxpAttrsResp:
		return &msg.Attrs, nil
	default:
		panic("unexpected message type returned from server")
	}
}

// expectStatus sends the request and returns an error if the operation
// resulted in an error.
func (s *Client) expectStatus(req ider) error {
	fxpCh, err := s.sendRequest(req)
	if err != nil {
	  return err
	}
	defer fxpCh.close()
	resp := fxpCh.waitForResponse()
	switch msg := resp.(type) {
	case *fxpStatusResp:
		if msg.Status != ok {
			return msg
		}
		return nil
	default:
		panic("unexpected message type returned from server")
	}
}

// expectHandle sends the request and returns the resulting file or directory
// handle that is expected to be returned.
func (s *Client) expectHandle(req ider) (string, error) {
	fxpCh, err := s.sendRequest(req)
	if err != nil {
	  return "", err
	}
	defer fxpCh.close()

	resp := fxpCh.waitForResponse()
	switch msg := resp.(type) {
	case *fxpStatusResp:
		return "", msg
	case *fxpHandleResp:
		return msg.Handle, nil
	default:
		panic("unexpected message type returned from server")
	}
}

// expectName sends the request and returns the file name data that is expected
// to be returned.
func (s *Client) expectName(req ider) ([]fxpNameData, error) {
	fxpCh, err := s.sendRequest(req)
	if err != nil {
	  return nil, err
	}
	defer fxpCh.close()
	resp := fxpCh.waitForResponse()
	switch msg := resp.(type) {
	case *fxpStatusResp:
		return nil, msg
	case *fxpNameResp:
		return msg.Data, nil
	default:
		panic("unexpected message type returned from server")
	}
}

// expectOneName sends the request and returns the single name that is expected
// to be returned.
func (s *Client) expectOneName(msg ider) (string, error) {
	n, err := s.expectName(msg)
	if err != nil {
		return "", err
	}
	if len(n) == 0 {
		return "", fmt.Errorf("no data returned")
	}
	if len(n) > 1 {
		return "", fmt.Errorf("more than one name returned")
	}
	return n[0].Filename, nil
}

// Stat returns file attributes for the given path.
func (s *Client) Stat(path string) (os.FileInfo, error) {
	fi, err := s.expectAttr(fxpStatMsg{Path: path})
	if err != nil {
		return nil, err
	}
	fi.name = path
	return fi, nil
}

// LStat returns file attributes for the given path.
func (s *Client) LStat(path string) (os.FileInfo, error) {
	fi, err := s.expectAttr(fxpLStatMsg{Path: path})
	if err != nil {
		return nil, err
	}
	fi.name = path
	return fi, nil
}

// Remove deletes the named file.
func (s *Client) Remove(name string) error {
	return s.expectStatus(fxpRemoveMsg{Filename: name})
}

// Mkdir creates a directory at the specified absolute path with the specified
// permissions.
func (s *Client) Mkdir(name string, perm os.FileMode) error {
	req := fxpMkdirMsg{Path: name}
	req.Attrs.setPermission(uint32(perm & os.ModePerm))
	return s.expectStatus(req)
}

// Rmdir deletes the named directory.
func (s *Client) Rmdir(name string) error {
	return s.expectStatus(fxpRmdirMsg{Path: name})
}

// ReadDir returns a list of file information for files in a specific
// directory.
func (s *Client) readDir(name string) ([]os.FileInfo, error) {
	h, err := s.expectHandle(fxpOpenDirMsg{Path: name})
	if err != nil {
		return nil, err
	}
	// close the handle regardless of whether an error is encountered.
	defer s.expectStatus(fxpCloseMsg{Handle: h})

	// TODO(ekg): the unmarshaling doesn't support slices of structs. Fix
	// this and change the visibility of this method.
	return nil, nil

	fi := []os.FileInfo{}
	for {
		names, err := s.expectName(fxpReadDirMsg{Handle: h})
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		for _, data := range names {
			data.Attrs.name = data.Filename
			fi = append(fi, data.Attrs)
		}
	}
	return fi, nil
}

const (
	fxpOpenRead   = 1
	fxpOpenWrite  = 2
	fxpOpenAppend = 4
	fxpOpenCreat  = 8
	fxpOpenTrunc  = 16
	fxpOpenExcl   = 32
)

func convertFlags(flags int) uint32 {
	var pflags uint32
	if flags&os.O_RDONLY > 0 {
		pflags |= fxpOpenRead
	}
	if flags&os.O_WRONLY > 0 {
		pflags |= fxpOpenWrite
	}
	if flags&os.O_RDWR > 0 {
		pflags |= fxpOpenRead | fxpOpenWrite
	}
	if flags&os.O_APPEND > 0 {
		pflags |= fxpOpenAppend
	}
	if flags&os.O_CREATE > 0 {
		pflags |= fxpOpenCreat
	}
	if flags&os.O_TRUNC > 0 {
		pflags |= fxpOpenTrunc
	}
	if flags&os.O_EXCL > 0 {
		pflags |= fxpOpenExcl
	}
	return pflags
}

// TODO(ekg): this can actually accept an entire attr structure...
func (s *Client) OpenFile(name string, flags int, attrs os.FileMode) (*File, error) {
	req := fxpOpenMsg{
		Filename: name,
		Pflags:   convertFlags(flags),
	}
	if attrs != 0 {
		req.Attrs.setPermission(uint32(attrs & os.ModePerm))
	}
	h, err := s.expectHandle(req)
	if err != nil {
		return nil, err
	}
	f := &File{
		name:     name,
		handle:   h,
		sftp:     s,
		isAppend: (flags&os.O_APPEND > 0),
	}
	return f, nil
}

func (s *Client) Open(name string) (*File, error) {
	return s.OpenFile(name, os.O_RDONLY, 0)
}

func (s *Client) Chown(path string, uid, gid int) error {
	req := fxpSetStatMsg{Path: path}
	req.Attrs.setID(uint32(uid), uint32(gid))
	return s.expectStatus(req)
}
func (s *Client) Readlink(name string) (string, error) {
	return s.expectOneName(fxpReadLinkMsg{Path: name})
}

// Symlink creates a symbolic link at the path newname pointing to the path
// oldname.
func (s *Client) Symlink(oldname, newname string) error {
	// Note that the paths are reversed in this implementation when
	// compared against the specification. This is because OpenSSH
	// "inadvertently" implemented this request incorrectly and decided to
	// just go with it. See the PROTOCOL file in OpenSSH for more
	// information.
	return s.expectStatus(fxpSymlinkMsg{LinkPath: oldname, TargetPath: newname})
}

func (s *Client) Realpath(path string) (string, error) {
	return s.expectOneName(fxpRealPathMsg{Path: path})
}

func (s *Client) Rename(oldname, newname string) error {
	return s.expectStatus(fxpRenameMsg{NewPath: newname, OldPath: oldname})
}

type File struct {
	name     string
	handle   string
	sftp     *Client
	offset   uint64
	isAppend bool
}

func (f *File) String() string {
	return f.name
}

func (f *File) Close() error {
	return f.sftp.expectStatus(fxpCloseMsg{Handle: f.handle})
}

const maxDataBytes = 1 << 15

func (f *File) Read(b []byte) (int, error) {
	n, err := f.ReadAt(b, int64(f.offset))
	f.offset += uint64(n)
	return n, err
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	req := fxpReadMsg{Handle: f.handle}
	fxpCh, err := f.sftp.chans.newChan()
	if err != nil {
		return
	}
	defer f.sftp.chans.remove(fxpCh.ReqID)
	req.SetID(fxpCh.ID())

	for len(b) > 0 {
		req.Offset = uint64(n) + uint64(off)
		req.Length = uint32(min(uint64(len(b)), maxDataBytes))
		if err = f.sftp.writePacket(ssh.Marshal(req)); err != nil {
			return
		}
		resp := fxpCh.waitForResponse()
		switch msg := resp.(type) {
		case *fxpStatusResp:
			if msg.Status == eof {
				err = io.EOF
				return
			}
			err = msg
			return
		case *fxpDataResp:
			n += copy(b, msg.Data)
			b = b[len(msg.Data):]
		default:
			panic("unexpected message type returned from server")
		}
	}
	return
}

func (f *File) Stat() (os.FileInfo, error) {
	fi, err := f.sftp.expectAttr(fxpFStatMsg{Handle: f.handle})
	if err != nil {
		return nil, err
	}
	fi.name = f.name
	return fi, nil
}

func (f *File) Write(b []byte) (int, error) {
	n, err := f.WriteAt(b, int64(f.offset))
	f.offset += uint64(n)
	return n, err
}

func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	req := fxpWriteMsg{Handle: f.handle}
	fxpCh, err := f.sftp.chans.newChan()
	if err != nil {
		return
	}
	defer f.sftp.chans.remove(fxpCh.ReqID)
	req.SetID(fxpCh.ID())

	for len(b) > 0 {
		req.Offset = uint64(n) + uint64(off)
		l := min(uint64(len(b)), maxDataBytes)
		req.Data = b[:l]
		if err = f.sftp.writePacket(ssh.Marshal(req)); err != nil {
			return
		}
		resp := fxpCh.waitForResponse()
		switch msg := resp.(type) {
		case *fxpStatusResp:
			if msg.Status != ok {
				err = msg
				return
			}
			n += int(l)
			b = b[l:]
		default:
			panic("unexpected message type returned from server")
		}
	}
	return
}

func (f *File) Seek(offset int64, whence int) (ret int64, err error) {
	switch whence {
	case 0:
		f.offset = uint64(offset)
	case 1:
		f.offset += uint64(offset)
	case 2:
		fi, err := f.Stat()
		if err != nil {
			return 0, err
		}
		f.offset = uint64(fi.Size() + offset)
	default:
		return 0, errors.New("invalid whence value")
	}
	return int64(f.offset), nil
}

// TODO(ekg): handle other methods
func (f *File) Chown(uid, gid int) error {
	req := fxpFSetStatMsg{Handle: f.handle}
	req.Attrs.setID(uint32(uid), uint32(gid))
	return f.sftp.expectStatus(req)
}

func (c *Client) Put(local, remote string) error {
	// TODO(ekg): fillout this function.
	return nil
}

func (c *Client) Get(remote, local string) error {
	// TODO(ekg): fillout this function.
	return nil
}
