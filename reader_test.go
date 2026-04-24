package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlowLogEntryUpdatePktPublicAndPrivateAddrs(t *testing.T) {
	tests := map[string]struct {
		srcAddr             string
		dstAddr             string
		expectedPublicAddr  string
		expectedPrivateAddr string
	}{
		"both public IPs - prefer destination": {
			srcAddr:             "8.8.8.8",
			dstAddr:             "1.1.1.1",
			expectedPublicAddr:  "1.1.1.1",
			expectedPrivateAddr: "",
		},
		"source public, destination private": {
			srcAddr:             "8.8.8.8",
			dstAddr:             "10.0.0.1",
			expectedPublicAddr:  "8.8.8.8",
			expectedPrivateAddr: "10.0.0.1",
		},
		"source private, destination public": {
			srcAddr:             "192.168.1.1",
			dstAddr:             "8.8.8.8",
			expectedPublicAddr:  "8.8.8.8",
			expectedPrivateAddr: "192.168.1.1",
		},
		"both private IPs - use source as private": {
			srcAddr:             "10.0.0.1",
			dstAddr:             "192.168.1.1",
			expectedPublicAddr:  "",
			expectedPrivateAddr: "10.0.0.1",
		},
		"loopback addresses are private": {
			srcAddr:             "127.0.0.1",
			dstAddr:             "8.8.8.8",
			expectedPublicAddr:  "8.8.8.8",
			expectedPrivateAddr: "127.0.0.1",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			entry := FlowLogEntry{
				PktSrcAddr: tc.srcAddr,
				PktDstAddr: tc.dstAddr,
			}

			entry.UpdatePktPublicAndPrivateAddrs()

			assert.Equal(t, tc.expectedPublicAddr, entry.PktPublicAddr)
			assert.Equal(t, tc.expectedPrivateAddr, entry.PktPrivateAddr)

			// Verify they are never the same (unless both empty)
			if entry.PktPublicAddr != "" || entry.PktPrivateAddr != "" {
				assert.NotEqual(t, entry.PktPublicAddr, entry.PktPrivateAddr)
			}
		})
	}
}

func TestFlowLogEntryIsLoadBalancerFlow(t *testing.T) {
	tests := map[string]struct {
		entry    FlowLogEntry
		ports    []int
		expected bool
	}{
		"SRC reporter with private src, matching port, public dst": {
			entry: FlowLogEntry{
				PktSrcAddr: "10.0.0.1",
				PktDstAddr: "8.8.8.8",
				SrcPort:    80,
				DstPort:    12345,
				Reporter:   ReporterSrc,
			},
			ports:    []int{80, 443},
			expected: true,
		},
		"SRC reporter with private src, non-matching port, public dst": {
			entry: FlowLogEntry{
				PktSrcAddr: "10.0.0.1",
				PktDstAddr: "8.8.8.8",
				SrcPort:    8080,
				DstPort:    12345,
				Reporter:   ReporterSrc,
			},
			ports:    []int{80, 443},
			expected: false,
		},
		"SRC reporter with public src, matching port, public dst": {
			entry: FlowLogEntry{
				PktSrcAddr: "8.8.8.8",
				PktDstAddr: "1.1.1.1",
				SrcPort:    80,
				DstPort:    12345,
				Reporter:   ReporterSrc,
			},
			ports:    []int{80, 443},
			expected: false,
		},
		"SRC reporter with private src, matching port, private dst": {
			entry: FlowLogEntry{
				PktSrcAddr: "10.0.0.1",
				PktDstAddr: "192.168.1.1",
				SrcPort:    80,
				DstPort:    12345,
				Reporter:   ReporterSrc,
			},
			ports:    []int{80, 443},
			expected: false,
		},
		"DEST reporter with private dst, matching port, public src": {
			entry: FlowLogEntry{
				PktSrcAddr: "8.8.8.8",
				PktDstAddr: "10.0.0.1",
				SrcPort:    12345,
				DstPort:    443,
				Reporter:   ReporterDest,
			},
			ports:    []int{80, 443},
			expected: true,
		},
		"DEST reporter with private dst, non-matching port, public src": {
			entry: FlowLogEntry{
				PktSrcAddr: "8.8.8.8",
				PktDstAddr: "10.0.0.1",
				SrcPort:    12345,
				DstPort:    8080,
				Reporter:   ReporterDest,
			},
			ports:    []int{80, 443},
			expected: false,
		},
		"DEST reporter with public dst, matching port, public src": {
			entry: FlowLogEntry{
				PktSrcAddr: "8.8.8.8",
				PktDstAddr: "1.1.1.1",
				SrcPort:    12345,
				DstPort:    443,
				Reporter:   ReporterDest,
			},
			ports:    []int{80, 443},
			expected: false,
		},
		"DEST reporter with private dst, matching port, private src": {
			entry: FlowLogEntry{
				PktSrcAddr: "192.168.1.1",
				PktDstAddr: "10.0.0.1",
				SrcPort:    12345,
				DstPort:    443,
				Reporter:   ReporterDest,
			},
			ports:    []int{80, 443},
			expected: false,
		},
		"empty reporter (AWS logs)": {
			entry: FlowLogEntry{
				PktSrcAddr: "10.0.0.1",
				PktDstAddr: "8.8.8.8",
				SrcPort:    80,
				DstPort:    12345,
				Reporter:   "",
			},
			ports:    []int{80, 443},
			expected: false,
		},
		"unknown reporter": {
			entry: FlowLogEntry{
				PktSrcAddr: "10.0.0.1",
				PktDstAddr: "8.8.8.8",
				SrcPort:    80,
				DstPort:    12345,
				Reporter:   "UNKNOWN",
			},
			ports:    []int{80, 443},
			expected: false,
		},
		"empty ports list": {
			entry: FlowLogEntry{
				PktSrcAddr: "10.0.0.1",
				PktDstAddr: "8.8.8.8",
				SrcPort:    80,
				DstPort:    12345,
				Reporter:   ReporterSrc,
			},
			ports:    []int{},
			expected: false,
		},
		"SRC reporter with 443 matching port": {
			entry: FlowLogEntry{
				PktSrcAddr: "10.0.0.1",
				PktDstAddr: "8.8.8.8",
				SrcPort:    443,
				DstPort:    12345,
				Reporter:   ReporterSrc,
			},
			ports:    []int{80, 443},
			expected: true,
		},
		"DEST reporter with 80 matching port": {
			entry: FlowLogEntry{
				PktSrcAddr: "8.8.8.8",
				PktDstAddr: "10.0.0.1",
				SrcPort:    12345,
				DstPort:    80,
				Reporter:   ReporterDest,
			},
			ports:    []int{80, 443},
			expected: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := tc.entry.IsLoadBalancerFlow(tc.ports)
			assert.Equal(t, tc.expected, result)
		})
	}
}
