package mail

import (
	"errors"
	"fmt"
	"io"
	"net/smtp"
	"net/textproto"
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
		// The DATA transaction never started: the message was not sent.
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		// The body never reached the terminator, so the server cannot have
		// completed the transaction: the message was not sent.
		return err
	}
	if err := w.Close(); err != nil {
		var tpErr *textproto.Error
		if errors.As(err, &tpErr) {
			// The server answered the final DATA reply with an explicit
			// rejection: the message was definitely not accepted.
			return err
		}
		// The full body was handed over; the reply could not be read. The
		// server may already have accepted the message.
		return fmt.Errorf("%w: %v", ErrDeliveryAccepted, err)
	}
	return nil
}

func (c clientConn) Quit() error { return c.cl.Quit() }

func (c clientConn) Close() error { return c.cl.Close() }
