package mail

import (
	"io"
	"net/smtp"
)

// clientConn adapts *smtp.Client to the testable conn interface.
type clientConn struct {
	cl *smtp.Client
}

func (c clientConn) Mail(from string) error { return c.cl.Mail(from) }

func (c clientConn) Rcpt(to string) error { return c.cl.Rcpt(to) }

func (c clientConn) Auth(a smtp.Auth) error { return c.cl.Auth(a) }

func (c clientConn) Data(r io.Reader) error {
	w, err := c.cl.Data()
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		return err
	}
	return w.Close()
}

func (c clientConn) Quit() error { return c.cl.Quit() }

func (c clientConn) Close() error { return c.cl.Close() }
