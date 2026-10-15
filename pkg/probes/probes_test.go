package probes

import (
	"encoding/hex"
	"testing"
)

func TestQUICVersionNegotiationProbe(t *testing.T) {
	for _, probe := range Probes {
		if probe.Name != "quic" {
			continue
		}
		if len(probe.Port) != 1 || probe.Port[0] != 443 || len(probe.Payloads) != 1 {
			t.Fatal("QUIC probe must target UDP/443 with one Initial packet")
		}
		packet, err := hex.DecodeString(probe.Payloads[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(packet) != 1200 || packet[0] != 0xc0 || hex.EncodeToString(packet[1:5]) != "0a0a0a0a" {
			t.Fatalf("invalid QUIC Initial probe: %d bytes", len(packet))
		}
		return
	}
	t.Fatal("QUIC probe missing")
}
