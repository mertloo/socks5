package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	socks5CmdConnect = 0x01
	socks5AtypHost   = 0x03
)

var (
	socks5NoauthReq  = []byte{0x05, 0x01, 0x00}
	socks5NoauthRes  = []byte{0x05, 0x00}
	socks5ConnectRes = []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}

	socks5AuthErr    = errors.New("socks5 auth error")
	socks5CmdErr     = errors.New("socks5 cmd error")
	socks5NotImplErr = errors.New("socks5 not impl error")
)

type dialer interface {
	Dial(addr string) (net.Conn, error)
}

type conn struct {
	server     *Server
	rwc        net.Conn
	buf        []byte
	remoteAddr string
	remoteConn net.Conn
	dialer
}

func (c *conn) serve() {
	defer c.close()
	fns := []func() error{c.auth, c.cmd}
	for _, fn := range fns {
		if err := fn(); err != nil {
			return
		}
	}
}

func (c *conn) auth() error {
	n, err := c.rwc.Read(c.buf)
	if n != 3 || !bytes.Equal(c.buf[:3], socks5NoauthReq) || err != nil {
		return socks5AuthErr
	}
	nw, errw := c.rwc.Write(socks5NoauthRes)
	if nw != len(socks5NoauthRes) || errw != nil {
		return socks5AuthErr
	}
	return nil
}

func (c *conn) cmd() error {
	n, err := c.rwc.Read(c.buf[:3])
	if n != 3 || c.buf[0] != 5 || c.buf[2] != 0 || err != nil {
		return socks5CmdErr
	}
	switch c.buf[1] {
	case socks5CmdConnect:
		if err = c.cmdConnect(); err != nil {
			return socks5CmdErr
		}
	default:
		return socks5CmdErr
	}
	return nil
}

func (c *conn) cmdConnect() error {
	n, err := c.rwc.Read(c.buf[:1])
	if n == 0 || err != nil {
		return err
	}
	if c.buf[0] != socks5AtypHost {
		return socks5NotImplErr
	}
	n, err = c.rwc.Read(c.buf[:1])
	if n == 0 || err != nil {
		return err
	}
	alen := c.buf[0]
	n, err = c.rwc.Read(c.buf[:alen+2])
	if n != int(alen)+2 || err != nil {
		return err
	}
	c.remoteAddr = fmt.Sprintf("%s:%d", c.buf[:alen], uint16(c.buf[alen])<<8|uint16(c.buf[alen+1]))
	t := time.Now()
	c.remoteConn, err = c.dial()
	if err != nil {
		return err
	}
	defer c.remoteConn.Close()
	c.rwc.Write(socks5ConnectRes)
	quit := make(chan struct{})
	go c.pipe(c.rwc, c.remoteConn, quit)
	c.pipe(c.remoteConn, c.rwc, quit)
	return nil
}

func (c *conn) pipe(dst, src net.Conn, quit chan struct{}) {
	for {
		_, err := io.Copy(dst, src)
		select {
		case <-quit:
			return
		default:
			if err != nil {
				close(quit)
				return
			}
		}
	}
}

func (c *conn) dial() (net.Conn, error) {
	if c.dialer != nil {
		return c.dialer.Dial(c.remoteAddr)
	}
	return net.Dial("tcp", c.remoteAddr)
}

func (c *conn) close() {
	c.rwc.Close()
}

type Server struct {
	Addr string
}

func (srv *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()
	for {
		rwc, e := l.Accept()
		if e != nil {
			continue
		}
		c := srv.newConn(rwc)
		go c.serve()
	}
}

func (srv *Server) newConn(rwc net.Conn) *conn {
	c := &conn{
		server: srv,
		rwc:    rwc,
		buf:    make([]byte, 1024),
	}
	return c
}
