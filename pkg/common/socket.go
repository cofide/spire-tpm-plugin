package common

import (
	"net"

	"github.com/google/go-attestation/attest"
)

type SocketChannel struct {
	net.Conn
}

func (sc *SocketChannel) Read(p []byte) (n int, err error) {
	return sc.Conn.Read(p)
}

func (sc *SocketChannel) Write(p []byte) (n int, err error) {
	return sc.Conn.Write(p)
}

func (sc *SocketChannel) Close() error {
	return sc.Conn.Close()
}

func (sc *SocketChannel) MeasurementLog() ([]byte, error) {
	// Not implemented
	return nil, nil
}

func OpenTPMSocket(socketPath string) (attest.CommandChannelTPM20, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	return &SocketChannel{Conn: conn}, nil
}
