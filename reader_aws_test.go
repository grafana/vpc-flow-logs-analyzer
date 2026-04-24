package main

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReaderReadNextLog(t *testing.T) {
	// Expected entries based on the test file content
	expectedEntries := []FlowLogEntry{
		{
			SrcAddr:          "10.3.6.187",
			DstAddr:          "10.63.37.34",
			SrcPort:          43944,
			DstPort:          443,
			PktSrcAddr:       "10.3.6.187",
			PktDstAddr:       "3.75.6.195",
			PktSrcAWSService: "-",
			PktDstAWSService: "EC2",
			Bytes:            208,
			Start:            1754321693,
			End:              1754321724,
			Accepted:         true,
			PktPublicAddr:    "3.75.6.195",
			PktPrivateAddr:   "10.3.6.187",
			Reporter:         "",
		},
		{
			SrcAddr:          "10.63.37.34",
			DstAddr:          "10.60.155.242",
			SrcPort:          443,
			DstPort:          54428,
			PktSrcAddr:       "3.78.206.74",
			PktDstAddr:       "10.60.155.242",
			PktSrcAWSService: "AMAZON",
			PktDstAWSService: "-",
			Bytes:            6942,
			Start:            1754321693,
			End:              1754321724,
			Accepted:         true,
			PktPublicAddr:    "3.78.206.74",
			PktPrivateAddr:   "10.60.155.242",
			Reporter:         "",
		},
		{
			SrcAddr:          "10.63.37.34",
			DstAddr:          "3.5.246.198",
			SrcPort:          54330,
			DstPort:          443,
			PktSrcAddr:       "10.63.37.34",
			PktDstAddr:       "3.5.246.198",
			PktSrcAWSService: "-",
			PktDstAWSService: "S3",
			Bytes:            40672,
			Start:            1754321693,
			End:              1754321724,
			Accepted:         true,
			PktPublicAddr:    "3.5.246.198",
			PktPrivateAddr:   "10.63.37.34",
			Reporter:         "",
		},
		{
			SrcAddr:          "85.214.204.244",
			DstAddr:          "10.63.37.34",
			SrcPort:          443,
			DstPort:          58253,
			PktSrcAddr:       "85.214.204.244",
			PktDstAddr:       "10.63.37.34",
			PktSrcAWSService: "-",
			PktDstAWSService: "-",
			Bytes:            4065,
			Start:            1754321693,
			End:              1754321724,
			Accepted:         true,
			PktPublicAddr:    "85.214.204.244",
			PktPrivateAddr:   "10.63.37.34",
			Reporter:         "",
		},
	}

	testFiles := []struct {
		name string
		path string
	}{
		{"uncompressed", "testdata/aws-test_flow_logs.log"},
		{"gzip compressed", "testdata/aws-test_flow_logs.log.gz"},
	}

	for _, testFile := range testFiles {
		t.Run(testFile.name, func(t *testing.T) {
			// Create reader for test file
			reader := NewReaderAWS(testFile.path)
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

func TestSplitFields(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected []string
	}{
		"simple fields": {
			input:    "one two three",
			expected: []string{"one", "two", "three"},
		},
		"VPC flow log line": {
			input:    "2 123456789012 eni-12345678 10.0.0.1 10.0.0.2 443 80 6 20 4000 1622505600 1622505660 ACCEPT OK 192.168.1.1 203.0.113.1 - EC2",
			expected: []string{"2", "123456789012", "eni-12345678", "10.0.0.1", "10.0.0.2", "443", "80", "6", "20", "4000", "1622505600", "1622505660", "ACCEPT", "OK", "192.168.1.1", "203.0.113.1", "-", "EC2"},
		},
		"single field": {
			input:    "single",
			expected: []string{"single"},
		},
		"empty string": {
			input:    "",
			expected: []string{},
		},
		"leading and trailing spaces": {
			input:    " start middle end ",
			expected: []string{"start", "middle", "end"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := splitFields(tc.input)
			assert.Equal(t, tc.expected, result)

			// Also ensure our implementation matches strings.Fields() for consistency
			stringsFieldsResult := strings.Fields(tc.input)
			assert.Equal(t, stringsFieldsResult, result)
		})
	}
}

func BenchmarkSplitFields(b *testing.B) {
	line := "2 123456789012 eni-12345678 10.0.0.1 10.0.0.2 443 80 6 20 4000 1622505600 1622505660 ACCEPT OK 192.168.1.1 203.0.113.1 - EC2"

	b.Run("splitFields", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = splitFields(line)
		}
	})

	b.Run("strings.Fields", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = strings.Fields(line)
		}
	})
}
