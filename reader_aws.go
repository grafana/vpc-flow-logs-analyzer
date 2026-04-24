package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ExpectedLogHeader defines the expected header format for VPC flow log files.
const ExpectedLogHeader = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status pkt-srcaddr pkt-dstaddr pkt-src-aws-service pkt-dst-aws-service"

// ReaderAWS handles reading and parsing AWS VPC flow log files.
type ReaderAWS struct {
	BaseReader
}

// NewReaderAWS creates a new ReaderAWS instance for the specified file path.
func NewReaderAWS(filePath string) *ReaderAWS {
	return &ReaderAWS{
		BaseReader: BaseReader{
			filePath: filePath,
		},
	}
}

// Open opens the log file and skips the header line.
func (r *ReaderAWS) Open() error {
	// Use the base reader's Open method first.
	if err := r.BaseReader.Open(); err != nil {
		return err
	}

	// Read and validate header line specific to AWS.
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return fmt.Errorf("failed to read header: %w", err)
		}
		return fmt.Errorf("file appears to be empty")
	}

	headerLine := strings.TrimSpace(r.scanner.Text())
	if headerLine != ExpectedLogHeader {
		return fmt.Errorf("invalid header format: expected %q, got %q", ExpectedLogHeader, headerLine)
	}

	return nil
}

// ReadNextLog reads and parses the next log entry from the file, returning io.EOF when done.
// The entry parameter is reused to avoid allocations - the same FlowLogEntry instance
// should be passed on each call to eliminate garbage collection pressure.
func (r *ReaderAWS) ReadNextLog(entry *FlowLogEntry) error {
	for {
		if !r.scanner.Scan() {
			if err := r.scanner.Err(); err != nil {
				return err
			}
			return io.EOF
		}

		line := r.scanner.Text()
		if line == "" {
			continue
		}

		fields := splitFields(line)
		if len(fields) < 17 {
			return fmt.Errorf("insufficient fields: got %d, expected at least 17", len(fields))
		}

		// Skip entries with non-OK log status (NODATA, SKIPDATA, etc.)
		logStatus := fields[13]
		if logStatus != "OK" {
			continue
		}

		bytes, err := strconv.ParseInt(fields[9], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid bytes field: %v", err)
		}

		start, err := strconv.ParseInt(fields[10], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid start timestamp field: %v", err)
		}

		end, err := strconv.ParseInt(fields[11], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid end timestamp field: %v", err)
		}

		srcPort, err := strconv.Atoi(fields[5])
		if err != nil {
			return fmt.Errorf("invalid source port field: %v", err)
		}

		dstPort, err := strconv.Atoi(fields[6])
		if err != nil {
			return fmt.Errorf("invalid destination port field: %v", err)
		}

		// Reuse the passed entry to avoid allocations.
		entry.SrcAddr = fields[3]
		entry.DstAddr = fields[4]
		entry.SrcPort = srcPort
		entry.DstPort = dstPort
		entry.PktSrcAddr = fields[14]
		entry.PktDstAddr = fields[15]
		entry.PktSrcAWSService = fields[16]
		entry.PktDstAWSService = fields[17]
		entry.Bytes = bytes
		entry.Start = start
		entry.End = end
		entry.Accepted = fields[12] == "ACCEPT"

		entry.UpdatePktPublicAndPrivateAddrs()

		return nil
	}
}

// splitFields splits a line into fields using space as delimiter with a stack-allocated array.
// Matches strings.Fields() behavior by skipping leading/trailing spaces and consecutive spaces.
func splitFields(line string) []string {
	var fieldsArray [20]string // Stack-allocated array
	fields := fieldsArray[:0]  // Slice with zero length but capacity 20

	start := -1
	for i := 0; i < len(line); i++ {
		if line[i] != ' ' {
			if start == -1 {
				start = i // Start of a new field
			}
		} else {
			if start != -1 {
				fields = append(fields, line[start:i])
				start = -1 // Reset for next field
			}
		}
	}
	// Add last field if we're in the middle of one
	if start != -1 {
		fields = append(fields, line[start:])
	}

	return fields
}
