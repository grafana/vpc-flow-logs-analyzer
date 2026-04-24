package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grafana/dskit/concurrency"
	"github.com/schollz/progressbar/v3"
)

// FileAnalysisResult holds the results from analyzing a single file.
type FileAnalysisResult struct {
	// endpoints maps endpoint IP addresses to their flow information.
	endpoints map[string]*Endpoint

	// minStartTime is the lowest start timestamp across all flow entries in this file.
	minStartTime int64

	// maxEndTime is the highest end timestamp across all flow entries in this file.
	maxEndTime int64
}

// Analyzer processes VPC flow log files and generates traffic analysis.
type Analyzer struct {
	filePaths     []string
	natGatewayIPs []string
	readerFactory ReaderFactory
	logger        Logger

	// filterStartTime is the start time filter for processing entries (zero value means no filtering).
	filterStartTime time.Time

	// filterEndTime is the end time filter for processing entries (zero value means no filtering).
	filterEndTime time.Time

	// autoDetectLoadBalancerFlows enables automatic detection of load balancer flows.
	autoDetectLoadBalancerFlows bool

	// autoDetectLoadBalancerTargetPorts is the list of ports to consider as load balancer target ports.
	autoDetectLoadBalancerTargetPorts []int

	// endpoints maps endpoint IP addresses to their flow information.
	endpoints map[string]*Endpoint

	// minStartTime is the lowest start timestamp across all flow entries.
	minStartTime int64

	// maxEndTime is the highest end timestamp across all flow entries.
	maxEndTime int64
}

// NewAnalyzer creates a new Analyzer instance with the specified file paths, NAT gateway IPs, filter times, load balancer detection settings, and logger.
func NewAnalyzer(filePaths []string, natGatewayIPs []string, filterStartTime, filterEndTime time.Time, readerFactory ReaderFactory, autoDetectLoadBalancerFlows bool, autoDetectLoadBalancerTargetPorts []int, logger Logger) *Analyzer {
	return &Analyzer{
		filePaths:                         filePaths,
		natGatewayIPs:                     natGatewayIPs,
		readerFactory:                     readerFactory,
		filterStartTime:                   filterStartTime,
		filterEndTime:                     filterEndTime,
		autoDetectLoadBalancerFlows:       autoDetectLoadBalancerFlows,
		autoDetectLoadBalancerTargetPorts: autoDetectLoadBalancerTargetPorts,
		logger:                            logger,
		endpoints:                         make(map[string]*Endpoint),
		minStartTime:                      math.MaxInt64,
		maxEndTime:                        0,
	}
}

// analyzeFile processes a single log file and returns the analysis results.
func analyzeFile(filePath string, natGatewayIPs []string, filterStartTime, filterEndTime time.Time, readerFactory ReaderFactory, autoDetectLoadBalancerFlows bool, autoDetectLoadBalancerTargetPorts []int) (*FileAnalysisResult, error) {
	result := &FileAnalysisResult{
		endpoints:    make(map[string]*Endpoint),
		minStartTime: math.MaxInt64,
		maxEndTime:   0,
	}

	// Pre-compute Unix timestamps for filtering
	var filterStartTimestamp, filterEndTimestamp int64
	if !filterStartTime.IsZero() {
		filterStartTimestamp = filterStartTime.Unix()
	}
	if !filterEndTime.IsZero() {
		filterEndTimestamp = filterEndTime.Unix()
	}

	reader := readerFactory(filePath)
	err := reader.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Reuse the same FlowLogEntry to avoid allocations.
	var entry FlowLogEntry

fileLoop:
	for {
		err := reader.ReadNextLog(&entry)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Filter entries by timestamp range if specified.
		if filterStartTimestamp > 0 && entry.End < filterStartTimestamp {
			continue
		}
		if filterEndTimestamp > 0 && entry.Start > filterEndTimestamp {
			continue
		}

		// Skip log entries with zero bytes.
		if entry.Bytes == 0 {
			continue
		}

		// Skip load balancer flows if auto-detection is enabled.
		if autoDetectLoadBalancerFlows && entry.IsLoadBalancerFlow(autoDetectLoadBalancerTargetPorts) {
			continue
		}

		// Track timestamps across all entries.
		if entry.Start < result.minStartTime {
			result.minStartTime = entry.Start
		}
		if entry.End > result.maxEndTime {
			result.maxEndTime = entry.End
		}

		// Exclude NAT Gateway traffic to avoid double counting.
		// When traffic flows through a NAT Gateway, there are duplicate log entries:
		// 1. From the source instance interface (with original packet addresses)
		// 2. From the NAT Gateway interface (with NAT Gateway IP in packet addresses)
		// To avoid counting the same traffic twice, we filter out entries where
		// the NAT Gateway IP appears in PktSrcAddr or PktDstAddr (intermediate records),
		// but keep entries where NAT Gateway IP appears only in SrcAddr/DstAddr (original records).
		for _, natGatewayIP := range natGatewayIPs {
			if entry.PktSrcAddr == natGatewayIP || entry.PktDstAddr == natGatewayIP {
				continue fileLoop
			}
		}

		// Group data transfer by public address if known, otherwise by destination address.
		addressKey := entry.PktPublicAddr
		if addressKey == "" {
			addressKey = entry.PktDstAddr
		}

		// Skip if destination address is local (starts with "10." or "100."), as we are only interested on public destinations
		if strings.HasPrefix(addressKey, "10.") || strings.HasPrefix(addressKey, "100.") {
			continue
		}

		// Update endpoint flow statistics.
		if endpoint, exists := result.endpoints[addressKey]; exists {
			endpoint.Bytes += entry.Bytes
		} else {
			result.endpoints[addressKey] = &Endpoint{
				Addr:    addressKey,
				Bytes:   entry.Bytes,
				Sources: make(map[string]*Source),
			}
		}

		// Determine source address key (PktPrivateAddr or fallback to PktSrcAddr).
		sourceKey := entry.PktPrivateAddr
		if sourceKey == "" {
			sourceKey = entry.PktSrcAddr
		}

		// Update source flow statistics.
		endpoint := result.endpoints[addressKey]
		if sourceFlow, exists := endpoint.Sources[sourceKey]; exists {
			sourceFlow.Bytes += entry.Bytes
		} else {
			endpoint.Sources[sourceKey] = &Source{
				Addr:  sourceKey,
				Bytes: entry.Bytes,
			}
		}
	}

	return result, nil
}

// Run processes all log files concurrently and builds traffic statistics.
func (a *Analyzer) Run() error {
	totalFiles := len(a.filePaths)

	bar := progressbar.NewOptions(totalFiles,
		progressbar.OptionSetWriter(a.logger.GetWriter()),
		progressbar.OptionSetDescription("Processing log files"),
		progressbar.OptionShowCount(),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionSetItsString("files"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))

	// Use a local mutex to protect concurrent access to analyzer fields
	var mu sync.Mutex
	var barMu sync.Mutex

	// Process files concurrently with GOMAXPROCS concurrency
	maxConcurrency := runtime.GOMAXPROCS(0)
	err := concurrency.ForEachJob(context.Background(), totalFiles, maxConcurrency, func(ctx context.Context, i int) error {
		filePath := a.filePaths[i]

		// Analyze the file
		result, err := analyzeFile(filePath, a.natGatewayIPs, a.filterStartTime, a.filterEndTime, a.readerFactory, a.autoDetectLoadBalancerFlows, a.autoDetectLoadBalancerTargetPorts)
		if err != nil {
			return err
		}

		// Merge results into analyzer fields with mutex protection. Results could be empty if all log entries
		// have been filtered out.
		if len(result.endpoints) > 0 {
			mu.Lock()
			// Merge endpoints
			for addr, endpoint := range result.endpoints {
				if existingEndpoint, exists := a.endpoints[addr]; exists {
					existingEndpoint.Bytes += endpoint.Bytes
					// Merge sources
					for sourceAddr, source := range endpoint.Sources {
						if existingSource, exists := existingEndpoint.Sources[sourceAddr]; exists {
							existingSource.Bytes += source.Bytes
						} else {
							existingEndpoint.Sources[sourceAddr] = source
						}
					}
				} else {
					a.endpoints[addr] = endpoint
				}
			}

			// Merge timestamps
			if result.minStartTime < a.minStartTime {
				a.minStartTime = result.minStartTime
			}
			if result.maxEndTime > a.maxEndTime {
				a.maxEndTime = result.maxEndTime
			}
			mu.Unlock()
		}

		// Update progress bar (with separate mutex to avoid deadlock)
		barMu.Lock()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memoryMB := float64(m.Alloc) / 1024 / 1024
		bar.Describe(fmt.Sprintf("Processing log files (Mem: %.1f MB)", memoryMB))
		bar.Add(1)
		barMu.Unlock()

		return nil
	})

	bar.Finish()
	fmt.Fprintf(a.logger.GetWriter(), "\n")
	return err
}

// GetEndpoints returns the endpoints map.
func (a *Analyzer) GetEndpoints() map[string]*Endpoint {
	return a.endpoints
}

// GetTotalBytes returns the total bytes across all endpoints.
func (a *Analyzer) GetTotalBytes() int64 {
	var total int64
	for _, endpoint := range a.endpoints {
		total += endpoint.Bytes
	}
	return total
}

// GetEndpointServicesByBytes returns a list of services sorted by bytes (highest first).
// This function expects that Endpoint.ServiceName has already been populated via ResolveServiceNames().
func (a *Analyzer) GetEndpointServicesByBytes() []*EndpointService {
	// Group endpoints by service name.
	serviceMap := make(map[string]*EndpointService)

	for _, endpoint := range a.endpoints {
		serviceName := endpoint.ServiceName
		// If service name is empty (unknown), use "IP: <addr>" as fallback for display.
		if serviceName == "" {
			serviceName = "IP: " + endpoint.Addr
		}

		if service, exists := serviceMap[serviceName]; exists {
			service.Bytes += endpoint.Bytes
			service.Endpoints = append(service.Endpoints, endpoint)
		} else {
			serviceMap[serviceName] = &EndpointService{
				Name:      serviceName,
				Bytes:     endpoint.Bytes,
				Endpoints: []*Endpoint{endpoint},
			}
		}
	}

	// Convert map to slice for sorting.
	services := make([]*EndpointService, 0, len(serviceMap))
	for _, service := range serviceMap {
		services = append(services, service)
	}

	// Sort by bytes (highest first).
	sort.Slice(services, func(i, j int) bool {
		return services[i].Bytes > services[j].Bytes
	})

	return services
}

// GetStartTime returns the earliest start timestamp across all flow entries as time.Time.
func (a *Analyzer) GetStartTime() time.Time {
	if a.minStartTime == math.MaxInt64 {
		return time.Time{} // Return zero time if no entries processed
	}
	return time.Unix(a.minStartTime, 0)
}

// GetEndTime returns the latest end timestamp across all flow entries as time.Time.
func (a *Analyzer) GetEndTime() time.Time {
	if a.maxEndTime == 0 {
		return time.Time{} // Return zero time if no entries processed
	}
	return time.Unix(a.maxEndTime, 0)
}

// ResolveServiceNames sets the ServiceName field on all endpoints and sources by resolving their IP addresses through the provided ServiceMapper.
func (a *Analyzer) ResolveServiceNames(serviceMapper *ServiceMapper) {
	// Collect all unique IP addresses from endpoints and sources.
	addrSet := make(map[string]struct{})

	for _, endpoint := range a.endpoints {
		addrSet[endpoint.Addr] = struct{}{}

		for _, source := range endpoint.Sources {
			addrSet[source.Addr] = struct{}{}
		}
	}

	// Convert set to slice for batch resolution.
	addrs := make([]string, 0, len(addrSet))
	for addr := range addrSet {
		addrs = append(addrs, addr)
	}

	// Resolve all addresses in a single call.
	addrToServiceName := serviceMapper.GetServiceNameByAddrs(addrs)

	// Apply resolved service names to endpoints and sources.
	for _, endpoint := range a.endpoints {
		endpoint.ServiceName = addrToServiceName[endpoint.Addr]

		for _, source := range endpoint.Sources {
			source.ServiceName = addrToServiceName[source.Addr]
		}
	}
}

// RemoveEndpointsByServiceNameRegexp removes endpoints whose service names match the specified regular expression.
func (a *Analyzer) RemoveEndpointsByServiceNameRegexp(regexPattern string) error {
	if regexPattern == "" {
		return nil
	}

	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return fmt.Errorf("invalid regular expression: %w", err)
	}

	// Remove endpoints whose service names match the regex.
	for addr, endpoint := range a.endpoints {
		if regex.MatchString(endpoint.ServiceName) {
			delete(a.endpoints, addr)
		}
	}

	return nil
}

// RemoveSourcesByServiceNameRegexp removes sources whose service names match the specified regular expression from all endpoints.
func (a *Analyzer) RemoveSourcesByServiceNameRegexp(regexPattern string) error {
	if regexPattern == "" {
		return nil
	}

	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return fmt.Errorf("invalid regular expression: %w", err)
	}

	// Iterate over all endpoints and remove matching sources, updating the Endpoint.Bytes to keep it consistent.
	for _, endpoint := range a.endpoints {
		for sourceAddr, source := range endpoint.Sources {
			if regex.MatchString(source.ServiceName) {
				endpoint.Bytes = max(endpoint.Bytes-source.Bytes, 0)
				delete(endpoint.Sources, sourceAddr)
			}
		}
	}

	return nil
}

// GetSourceServicesByBytes returns all source services across all endpoints, grouped by service name and sorted by bytes (highest first).
// This function expects that Source.ServiceName has already been populated via ResolveServiceNames().
func (a *Analyzer) GetSourceServicesByBytes() []*SourceService {
	// Group source services by service name, tracking which endpoints they send traffic to.
	serviceMap := make(map[string]*SourceService)

	for _, endpoint := range a.endpoints {
		for _, source := range endpoint.Sources {
			sourceName := source.ServiceName
			// If service name is empty (unknown), use "IP: <addr>" as fallback for display.
			if sourceName == "" {
				sourceName = "IP: " + source.Addr
			}

			// Get endpoint service name for grouping
			endpointServiceName := endpoint.ServiceName
			if endpointServiceName == "" {
				endpointServiceName = "IP: " + endpoint.Addr
			}

			if existingService, exists := serviceMap[sourceName]; exists {
				existingService.Bytes += source.Bytes

				// Find existing endpoint by service name and merge bytes
				endpointFound := false
				for _, existingEndpoint := range existingService.Endpoints {
					if existingEndpoint.ServiceName == endpointServiceName {
						existingEndpoint.Bytes += source.Bytes
						endpointFound = true
						break
					}
				}

				// If endpoint service not found, create a copy and add it
				if !endpointFound {
					endpointCopy := &Endpoint{
						Addr:        "",           // Don't populate Addr since we're merging by service name
						Bytes:       source.Bytes, // Store bytes sent from this source to this endpoint
						ServiceName: endpointServiceName,
						Sources:     nil, // Don't copy sources to avoid circular references
					}
					existingService.Endpoints = append(existingService.Endpoints, endpointCopy)
				}
			} else {
				// Create endpoint copy for new source service
				endpointCopy := &Endpoint{
					Addr:        "",           // Don't populate Addr since we're merging by service name
					Bytes:       source.Bytes, // Store bytes sent from this source to this endpoint
					ServiceName: endpointServiceName,
					Sources:     nil, // Don't copy sources to avoid circular references
				}

				serviceMap[sourceName] = &SourceService{
					Name:      sourceName,
					Bytes:     source.Bytes,
					Endpoints: []*Endpoint{endpointCopy},
				}
			}
		}
	}

	// Convert map to slice for sorting.
	sourceServices := make([]*SourceService, 0, len(serviceMap))
	for _, service := range serviceMap {
		// Sort endpoints within each source service by bytes (highest first).
		sort.Slice(service.Endpoints, func(i, j int) bool {
			return service.Endpoints[i].Bytes > service.Endpoints[j].Bytes
		})
		sourceServices = append(sourceServices, service)
	}

	// Sort by bytes (highest first).
	sort.Slice(sourceServices, func(i, j int) bool {
		return sourceServices[i].Bytes > sourceServices[j].Bytes
	})

	return sourceServices
}
