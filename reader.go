package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	// LogTypeAWS represents AWS VPC flow logs.
	LogTypeAWS = "aws"
	// LogTypeGCP represents GCP VPC flow logs.
	LogTypeGCP = "gcp"
	// LogTypeAzure represents Azure VPC flow logs.
	LogTypeAzure = "azure"

	// ReporterSrc indicates the flow was reported by the source.
	ReporterSrc = "SRC"
	// ReporterDest indicates the flow was reported by the destination.
	ReporterDest = "DEST"
)

// FlowLogEntry represents a single VPC flow log entry.
type FlowLogEntry struct {
	// SrcAddr is the source IP address of the network interface.
	SrcAddr string

	// DstAddr is the destination IP address of the network interface.
	DstAddr string

	// SrcPort is the source port of the flow.
	SrcPort int

	// DstPort is the destination port of the flow.
	DstPort int

	// PktSrcAddr is the original source IP address of the packet.
	PktSrcAddr string

	// PktDstAddr is the original destination IP address of the packet.
	PktDstAddr string

	// PktSrcAWSService is the AWS service name for the source IP (if known).
	PktSrcAWSService string

	// PktDstAWSService is the AWS service name for the destination IP (if known).
	PktDstAWSService string

	// Bytes is the number of bytes transferred in this flow.
	Bytes int64

	// Start is the start time of the flow as Unix timestamp.
	Start int64

	// End is the end time of the flow as Unix timestamp.
	End int64

	// Accepted indicates whether the flow was accepted (true) or rejected (false).
	Accepted bool

	// PktPublicAddr is the public IP address from the flow (src or dst).
	// If they're public then it is the dst addr.
	// If they're both private then it's empty.
	// This field is guaranteed to never be the same as PktPrivateAddr.
	PktPublicAddr string

	// PktPrivateAddr is the private IP address from the flow (src or dst).
	// If both IPs are private, it's the source address.
	// If both IPs are public, this field is empty.
	// This field is guaranteed to never be the same as PktPublicAddr.
	PktPrivateAddr string

	// Reporter indicates which side reported the flow (only populated for GCP logs).
	// Can be ReporterSrc or ReporterDest, or empty string for AWS and Azure logs.
	Reporter string
}

// UpdatePktPublicAndPrivateAddrs determines and sets the public and private IP addresses for a flow log entry.
func (entry *FlowLogEntry) UpdatePktPublicAndPrivateAddrs() {
	// Determine the public and private IP addresses.
	srcIsPrivate := isPrivateIP(entry.PktSrcAddr)
	dstIsPrivate := isPrivateIP(entry.PktDstAddr)

	if !srcIsPrivate && !dstIsPrivate {
		// Both are public, prefer destination as public, no private address.
		entry.PktPublicAddr = entry.PktDstAddr
		entry.PktPrivateAddr = ""
	} else if !srcIsPrivate {
		// Source is public, destination is private.
		entry.PktPublicAddr = entry.PktSrcAddr
		entry.PktPrivateAddr = entry.PktDstAddr
	} else if !dstIsPrivate {
		// Destination is public, source is private.
		entry.PktPublicAddr = entry.PktDstAddr
		entry.PktPrivateAddr = entry.PktSrcAddr
	} else {
		// Both are private, no public address, use source as private.
		entry.PktPublicAddr = ""
		entry.PktPrivateAddr = entry.PktSrcAddr
	}
}

// IsLoadBalancerFlow determines if the flow log entry represents a load balancer flow. We consider a flow to/from
// a load balancer if the flow is between a private IP port among the input ones (well known public service ports, e.g.
// 80 and 443) and a public IP.
func (entry *FlowLogEntry) IsLoadBalancerFlow(ports []int) bool {
	if entry.Reporter == ReporterSrc {
		return isPrivateIP(entry.PktSrcAddr) && slices.Contains(ports, entry.SrcPort) && !isPrivateIP(entry.PktDstAddr)
	} else if entry.Reporter == ReporterDest {
		return isPrivateIP(entry.PktDstAddr) && slices.Contains(ports, entry.DstPort) && !isPrivateIP(entry.PktSrcAddr)
	}

	// Otherwise, no.
	return false
}

// BaseReader provides common functionality for reading flow log files.
type BaseReader struct {
	filePath   string
	file       *os.File
	gzipReader *gzip.Reader
	scanner    *bufio.Scanner
	reader     *bufio.Reader
	logType    string
}

// Open opens the log file for reading with buffering and optional gzip decompression.
func (r *BaseReader) Open() error {
	file, err := os.Open(r.filePath)
	if err != nil {
		return err
	}
	r.file = file

	// Buffer the file reader with 4MB buffer for better syscall performance.
	bufferedFile := bufio.NewReaderSize(file, 4*1024*1024)
	var reader io.Reader = bufferedFile

	// If file ends with .gz, wrap with gzip reader and buffer it too.
	if strings.HasSuffix(r.filePath, ".gz") {
		gzipReader, err := gzip.NewReader(bufferedFile)
		if err != nil {
			file.Close()
			return err
		}
		r.gzipReader = gzipReader
		// Buffer the gzip reader output with 2MB buffer.
		reader = bufio.NewReaderSize(gzipReader, 2*1024*1024)
	}

	// For Azure logs, use bufio.Reader, as Azure use a long single JSON array.
	// for others, use bufio.Scanner.
	switch r.logType {
	case LogTypeAzure:
		r.reader = bufio.NewReader(reader)
	default:
		r.scanner = bufio.NewScanner(reader)
	}

	return nil
}

// Close closes the opened file and gzip reader if present.
func (r *BaseReader) Close() error {
	var err error
	if r.gzipReader != nil {
		err = r.gzipReader.Close()
	}
	if r.file != nil {
		if fileErr := r.file.Close(); fileErr != nil && err == nil {
			err = fileErr
		}
	}
	return err
}

// Reader interface for reading flow log entries.
type Reader interface {
	Open() error
	Close() error
	ReadNextLog(entry *FlowLogEntry) error
}

// ReaderFactory is a function that creates a new Reader for a given file path.
type ReaderFactory func(filePath string) Reader

// NewReaderFactory creates a ReaderFactory for the specified log type.
func NewReaderFactory(logType string) (ReaderFactory, error) {
	switch logType {
	case LogTypeAWS:
		return func(filePath string) Reader {
			r := NewReaderAWS(filePath)
			r.BaseReader.logType = LogTypeAWS
			return r
		}, nil
	case LogTypeGCP:
		return func(filePath string) Reader {
			r := NewReaderGCP(filePath)
			r.BaseReader.logType = LogTypeGCP
			return r
		}, nil
	case LogTypeAzure:
		return func(filePath string) Reader {
			r := NewReaderAzure(filePath)
			r.BaseReader.logType = LogTypeAzure
			return r
		}, nil
	default:
		return nil, fmt.Errorf("unsupported log type: %s", logType)
	}
}

// FindLogFiles recursively finds all log files (.log, .log.gz, and .json) in the specified directory.
func FindLogFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".log") || strings.HasSuffix(path, ".log.gz") || strings.HasSuffix(path, ".json")) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
