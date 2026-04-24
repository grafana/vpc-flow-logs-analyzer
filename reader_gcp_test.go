package main

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReaderGCPReadNextLog(t *testing.T) {
	// Expected entries based on the GCP test file content
	expectedEntries := []FlowLogEntry{
		{
			SrcAddr:          "198.51.100.75",
			DstAddr:          "192.0.2.2",
			SrcPort:          49444,
			DstPort:          3389,
			PktSrcAddr:       "198.51.100.75",
			PktDstAddr:       "192.0.2.2",
			PktSrcAWSService: "",
			PktDstAWSService: "",
			Bytes:            491,
			Start:            1522763257, // 2018-04-03T13:47:37.301723960Z
			End:              1522763258, // 2018-04-03T13:47:38.401Z
			Accepted:         true,
			PktPublicAddr:    "192.0.2.2", // Both public, prefer destination
			PktPrivateAddr:   "",          // No private address
			Reporter:         "DEST",
		},
		{
			SrcAddr:          "192.0.2.2",
			DstAddr:          "198.51.100.75",
			SrcPort:          3389,
			DstPort:          49444,
			PktSrcAddr:       "192.0.2.2",
			PktDstAddr:       "198.51.100.75",
			PktSrcAWSService: "",
			PktDstAWSService: "",
			Bytes:            756,
			Start:            1522763252, // 2018-04-03T13:47:32.805417512Z
			End:              1522763253, // 2018-04-03T13:47:33.937764566Z
			Accepted:         true,
			PktPublicAddr:    "198.51.100.75", // Both public, prefer destination
			PktPrivateAddr:   "",              // No private address
			Reporter:         "SRC",
		},
		{
			SrcAddr:          "192.0.2.2",
			DstAddr:          "192.0.2.3",
			SrcPort:          3389,
			DstPort:          65535,
			PktSrcAddr:       "192.0.2.2",
			PktDstAddr:       "192.0.2.3",
			PktSrcAWSService: "",
			PktDstAWSService: "",
			Bytes:            1020,
			Start:            1522763251, // 2018-04-03T13:47:31.805417512Z
			End:              1522763313, // 2018-04-03T13:48:33.937764566Z
			Accepted:         true,
			PktPublicAddr:    "192.0.2.3", // Both public, prefer destination
			PktPrivateAddr:   "",          // No private address
			Reporter:         "SRC",
		},
		{
			SrcAddr:          "192.0.2.2",
			DstAddr:          "192.0.2.3",
			SrcPort:          0, // No src_port in this entry (ICMP)
			DstPort:          0, // No dest_port in this entry (ICMP)
			PktSrcAddr:       "192.0.2.2",
			PktDstAddr:       "192.0.2.3",
			PktSrcAWSService: "",
			PktDstAWSService: "",
			Bytes:            1020,
			Start:            0,          // No start_time in this entry
			End:              1522763313, // 2018-04-03T13:48:33.937764566Z
			Accepted:         true,
			PktPublicAddr:    "192.0.2.3", // Both public, prefer destination
			PktPrivateAddr:   "",          // No private address
			Reporter:         "SRC",
		},
	}

	testFiles := []struct {
		name string
		path string
	}{
		{"jsonl format", "testdata/gcp-test_flow_logs.json"},
	}

	for _, testFile := range testFiles {
		t.Run(testFile.name, func(t *testing.T) {
			// Create reader for test file
			reader := NewReaderGCP(testFile.path)
			err := reader.Open()
			require.NoError(t, err)
			defer reader.Close()

			// Read and verify each entry
			var entry FlowLogEntry
			for _, expected := range expectedEntries {
				err := reader.ReadNextLog(&entry)
				require.NoError(t, err)

				assert.Equal(t, expected, entry)

				// Verify PktPublicAddr and PktPrivateAddr are never the same
				assert.NotEqual(t, entry.PktPublicAddr, entry.PktPrivateAddr)
			}

			// Verify that the next read returns EOF
			err = reader.ReadNextLog(&entry)
			assert.Equal(t, io.EOF, err)
		})
	}
}
