package scan

import (
	"bytes"
	"net"
	"testing"

	"github.com/carlospolop/udpx/pkg/probes"
)

func TestScannerKeepsFullResponse(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	response := bytes.Repeat([]byte("A"), 512)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, peer, err := server.ReadFrom(buf)
		if err == nil {
			_, err = server.WriteTo(response, peer)
		}
		done <- err
	}()

	port := server.LocalAddr().(*net.UDPAddr).Port
	results := make(chan Message, 1)
	Scanner{
		Target:  "127.0.0.1",
		Probes:  []probes.Probe{{Name: "test", Payloads: []string{"00"}, Port: []int{port}}},
		Arg_st:  1000,
		Channel: results,
	}.Run()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-results:
		if !bytes.Equal(result.ResponseData, response) {
			t.Fatalf("response bytes = %d, want %d", len(result.ResponseData), len(response))
		}
	default:
		t.Fatal("scanner did not report the UDP response")
	}
}
