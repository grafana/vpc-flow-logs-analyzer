package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// AzureFlowLogRecord for sampleAzureFlowLog (matches "flowRecords" not "properties")
type AzureFlowLogRecord struct {
	Time              string           `json:"time"`
	FlowLogGUID       string           `json:"flowLogGUID"`
	MacAddress        string           `json:"macAddress"`
	Category          string           `json:"category"`
	FlowLogResourceID string           `json:"flowLogResourceID"`
	TargetResourceID  string           `json:"targetResourceID"`
	FlowLogVersion    int              `json:"flowLogVersion"`
	OperationName     string           `json:"operationName"`
	FlowRecords       AzureFlowRecords `json:"flowRecords"`
}

type AzureFlowRecords struct {
	Flows []AzureFlowRecordFlow `json:"flows"`
}

type AzureFlowRecordFlow struct {
	AclID      string           `json:"aclID"`
	FlowGroups []AzureFlowGroup `json:"flowGroups"`
}

type AzureFlowGroup struct {
	Rule       string   `json:"rule"`
	FlowTuples []string `json:"flowTuples"`
}

// AzureFlowLogRoot is the top-level structure for the file.
type AzureFlowLogRoot struct {
	Records []AzureFlowLogRecord `json:"records"`
}

// ReaderAzure handles reading and parsing Azure VNET flow log files.
type ReaderAzure struct {
	BaseReader
	flowTuples [][]string // Flattened flow tuples for iteration
	index      int
}

// NewReaderAzure creates a new ReaderAzure instance for the specified file path.
func NewReaderAzure(filePath string) *ReaderAzure {
	return &ReaderAzure{
		BaseReader: BaseReader{
			filePath: filePath,
		},
	}
}

// Open opens the log file for reading.
func (r *ReaderAzure) Open() error {
	return r.BaseReader.Open()
}

// ReadNextLog reads and parses the next log entry from the file, returning io.EOF when done.
func (r *ReaderAzure) ReadNextLog(entry *FlowLogEntry) error {
	// If we have pre-parsed flow tuples, return them one by one.
	for {
		if r.flowTuples != nil && r.index < len(r.flowTuples) {
			return r.parseTuple(r.flowTuples[r.index], entry)
		}

		// Otherwise, read the next line and parse it using bufio.Reader.
		line, err := r.reader.ReadString('\n')
		if err != nil {
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var root AzureFlowLogRoot
		if err := json.Unmarshal([]byte(line), &root); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}

		// Flatten all flow tuples in this file.
		var tuples [][]string
		for _, record := range root.Records {
			for _, flow := range record.FlowRecords.Flows {

				for _, group := range flow.FlowGroups {

					for _, tupleStr := range group.FlowTuples {

						fields := strings.Split(tupleStr, ",")
						tuples = append(tuples, fields)
					}
				}
			}
		}
		r.flowTuples = tuples
		r.index = 0

		// If we have tuples, parse the first one.
		if len(r.flowTuples) > 0 {
			return r.parseTuple(r.flowTuples[r.index], entry)
		}
	}
}

// parseTuple parses a single Azure flow tuple into a FlowLogEntry.
func (r *ReaderAzure) parseTuple(tuple []string, entry *FlowLogEntry) error {
	// Azure flowTuple format (v2+): [srcIp, destIp, srcPort, destPort, protocol, trafficFlow, flowState, packets, bytes, startTime, endTime, ...]
	// See: https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview#flow-logs-version-2
	// timestamp, srcIp, destIp, srcPort, destPort, protocol, trafficFlow, flowState, packets, bytes, startTime, endTime
	//"1757681933059,10.68.3.215,10.68.17.102,39427,53,17,O,E,NX,1,160,1,253",

	if len(tuple) < 13 {
		return fmt.Errorf("unexpected flowTuple length: %d", len(tuple))
	}

	entry.SrcAddr = tuple[1]
	entry.DstAddr = tuple[2]

	srcPort, err := strconv.Atoi(tuple[3])
	if err != nil {
		return fmt.Errorf("failed to parse srcPort %q: %w", tuple[3], err)
	}
	entry.SrcPort = srcPort

	dstPort, err := strconv.Atoi(tuple[4])
	if err != nil {
		return fmt.Errorf("failed to parse dstPort %q: %w", tuple[4], err)
	}
	entry.DstPort = dstPort

	entry.PktSrcAddr = tuple[1]
	entry.PktDstAddr = tuple[2]

	bytes, err := strconv.ParseInt(tuple[10], 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse bytes %q: %w", tuple[10], err)
	}
	entry.Bytes = bytes

	start, err := strconv.ParseInt(tuple[11], 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse startTime %q: %w", tuple[11], err)
	}
	entry.Start = start

	end, err := strconv.ParseInt(tuple[12], 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse endTime %q: %w", tuple[12], err)
	}
	entry.End = end

	entry.Accepted = tuple[7] == "A"
	entry.Reporter = "" // Azure logs do not have a reporter field

	entry.UpdatePktPublicAndPrivateAddrs()

	r.index++
	return nil
}
