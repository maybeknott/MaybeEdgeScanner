package main

import (
	"context"
	"net"
	"time"
)

type DPIObfuscationOptions struct {
	EnablePayloadSplitting bool `json:"enable_payload_splitting"`
	SplitByteBoundary      int  `json:"split_byte_boundary"`
}

type ObfuscatedConn struct {
	net.Conn
	SplitBoundary int
}

func (c *ObfuscatedConn) Write(b []byte) (int, error) {
	if len(b) > c.SplitBoundary {
		n1, err := c.Conn.Write(b[:c.SplitBoundary])
		if err != nil {
			return n1, err
		}
		time.Sleep(50 * time.Microsecond)
		n2, err := c.Conn.Write(b[c.SplitBoundary:])
		return n1 + n2, err
	}
	return c.Conn.Write(b)
}

func DialObfuscatedSocket(ctx context.Context, network, addr string, timeout time.Duration, opts DPIObfuscationOptions) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if opts.EnablePayloadSplitting && opts.SplitByteBoundary > 0 {
		return &ObfuscatedConn{Conn: rawConn, SplitBoundary: opts.SplitByteBoundary}, nil
	}
	return rawConn, nil
}
