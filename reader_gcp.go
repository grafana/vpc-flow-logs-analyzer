package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// GCPCloudLogEntry represents the Cloud Logging wrapper structure.
type GCPCloudLogEntry struct {
	JSONPayload GCPFlowLogRaw `json:"jsonPayload"`
}

// GCPFlowLogRaw represents the raw GCP flow log JSON structure with only needed fields.
type GCPFlowLogRaw struct {
	BytesSent  string `json:"bytes_sent"`
	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time"`
	Reporter   string `json:"reporter"`
	Connection struct {
		SrcIP   string `json:"src_ip"`
		DstIP   string `json:"dest_ip"`
		SrcPort int    `json:"src_port"`
		DstPort int    `json:"dest_port"`
	} `json:"connection"`
}

// ReaderGCP handles reading and parsing GCP VPC flow log files.
type ReaderGCP struct {
	BaseReader
}

// NewReaderGCP creates a new ReaderGCP instance for the specified file path.
func NewReaderGCP(filePath string) *ReaderGCP {
	return &ReaderGCP{
		BaseReader: BaseReader{
			filePath: filePath,
		},
	}
}

// Open opens the log file for reading. GCP flow logs don't have headers like AWS.
func (r *ReaderGCP) Open() error {
	// GCP logs don't have headers, so we just use the base reader's Open method.
	return r.BaseReader.Open()
}

// ReadNextLog reads and parses the next log entry from the file, returning io.EOF when done.
// The entry parameter is reused to avoid allocations - the same FlowLogEntry instance
// should be passed on each call to eliminate garbage collection pressure.
func (r *ReaderGCP) ReadNextLog(entry *FlowLogEntry) error {
	for {
		if !r.scanner.Scan() {
			if err := r.scanner.Err(); err != nil {
				return err
			}
			return io.EOF
		}

		line := strings.TrimSpace(r.scanner.Text())
		if line == "" {
			continue
		}

		var cloudLogEntry GCPCloudLogEntry
		if err := json.Unmarshal([]byte(line), &cloudLogEntry); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}

		raw := cloudLogEntry.JSONPayload

		// Parse bytes field.
		bytes, err := strconv.ParseInt(raw.BytesSent, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid bytes_sent field: %w", err)
		}

		// Parse timestamps.
		var start, end int64
		if raw.StartTime != "" {
			startTime, err := time.Parse(time.RFC3339Nano, raw.StartTime)
			if err != nil {
				return fmt.Errorf("invalid start_time field: %w", err)
			}
			start = startTime.Unix()
		}

		if raw.EndTime != "" {
			endTime, err := time.Parse(time.RFC3339Nano, raw.EndTime)
			if err != nil {
				return fmt.Errorf("invalid end_time field: %w", err)
			}
			end = endTime.Unix()
		}

		// Map GCP fields to FlowLogEntry.
		// GCP doesn't have separate interface vs packet IPs like AWS, so we use connection IPs for both.
		entry.SrcAddr = raw.Connection.SrcIP
		entry.DstAddr = raw.Connection.DstIP
		entry.SrcPort = raw.Connection.SrcPort
		entry.DstPort = raw.Connection.DstPort
		entry.PktSrcAddr = raw.Connection.SrcIP
		entry.PktDstAddr = raw.Connection.DstIP
		entry.Bytes = bytes
		entry.Start = start
		entry.End = end
		entry.Accepted = true
		entry.Reporter = raw.Reporter

		entry.UpdatePktPublicAndPrivateAddrs()

		return nil
	}
}
