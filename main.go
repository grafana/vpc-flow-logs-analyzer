package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/grafana/dskit/flagext"
)

func main() {
	app := kingpin.New("vpc-flow-logs-analyzer", "Analyze AWS, GCP, and Azure VPC flow logs for data transfer patterns")
	inputs := app.Arg("inputs", "Log files or directories to analyze").Required().Strings()

	configFile := app.Flag("config", "Path to YAML configuration file for resource tagging").Short('c').PlaceHolder("<FILE>").String()
	clusters := flagext.StringSliceCSV{}
	app.Flag("cluster", "Comma-separated list of Kubernetes cluster names for service name mapping").Required().SetValue(&clusters)
	logType := app.Flag("log-type", "Type of flow logs to process: aws, gcp, or azure").Default(LogTypeAWS).Enum(LogTypeAWS, LogTypeGCP, LogTypeAzure)

	awsNatGatewayIPs := flagext.StringSliceCSV{}
	app.Flag("aws-natgateway-ips", "Comma-separated list of AWS NAT Gateway IP addresses to exclude from double counting").PlaceHolder("<IPS>").SetValue(&awsNatGatewayIPs)

	autoDetectLoadBalancerFlows := app.Flag("auto-detect-load-balancer-flows", "Enable automatic detection of load balancer flows").Bool()
	autoDetectLoadBalancerTargetPorts := flagext.StringSliceCSV{}
	app.Flag("auto-detect-load-balancer-target-ports", "Comma-separated list of ports to consider as load balancer target ports").Default("80,443,8000").SetValue(&autoDetectLoadBalancerTargetPorts)

	mimirURL := app.Flag("mimir-url", "Prometheus-compatible API URL for Kubernetes IP resolution").PlaceHolder("<URL>").String()
	mimirUsername := app.Flag("mimir-username", "HTTP basic auth username for the Prometheus-compatible API").PlaceHolder("<USER>").String()
	mimirPassword := app.Flag("mimir-password", "HTTP basic auth password for the Prometheus-compatible API").PlaceHolder("<PASS>").String()

	filterStartTimeStr := app.Flag("filter-start-time", "Filter logs from this start time (RFC3339 format, e.g., 2006-01-02T15:04:05Z)").PlaceHolder("<RFC3339>").String()
	filterEndTimeStr := app.Flag("filter-end-time", "Filter logs until this end time (RFC3339 format, e.g., 2006-01-02T15:04:05Z)").PlaceHolder("<RFC3339>").String()
	excludeEndpointServiceNamesRegexp := app.Flag("exclude-endpoint-service-names-regexp", "Regular expression for endpoint service names to exclude from the analysis").PlaceHolder("<REGEXP>").String()
	excludeSourceServiceNamesRegexp := app.Flag("exclude-source-service-names-regexp", "Regular expression for source service names to exclude from the analysis").PlaceHolder("<REGEXP>").String()

	showDetails := app.Flag("show-details", "Show top sources for each service when printing results").Bool()
	maxEndpoints := app.Flag("max-endpoints", "Maximum number of endpoints to print").Default("25").Int()
	maxSourcesPerEndpoint := app.Flag("max-sources-per-endpoint", "Maximum number of sources per endpoint to print when --show-details is enabled").Default("10").Int()
	maxSources := app.Flag("max-sources", "Maximum number of source services to print").Default("25").Int()
	maxEndpointsPerSource := app.Flag("max-endpoints-per-source", "Maximum number of endpoints per source to print when --show-details is enabled").Default("10").Int()

	cacheDir := app.Flag("cache-dir", "Persistent service name cache directory (default: $XDG_CACHE_HOME/vpc-flow-logs-analyzer)").PlaceHolder("<DIR>").String()

	cpuProfile := app.Flag("cpuprofile", "Write CPU profile to file").PlaceHolder("<FILE>").String()
	memProfile := app.Flag("memprofile", "Write memory profile to file").PlaceHolder("<FILE>").String()

	kingpin.MustParse(app.Parse(os.Args[1:]))

	logger := NewStderrLogger()

	// Validate that --aws-natgateway-ips is provided when --log-type is "aws"
	if *logType == LogTypeAWS && len(awsNatGatewayIPs) == 0 {
		logger.LogError("--aws-natgateway-ips is required when --log-type is aws")
		os.Exit(1)
	}

	// Parse filter times
	var filterStartTime, filterEndTime time.Time
	var err error

	if *filterStartTimeStr != "" {
		filterStartTime, err = time.Parse(time.RFC3339, *filterStartTimeStr)
		if err != nil {
			logger.LogError("parsing filter-start-time: %v", err)
			os.Exit(1)
		}
	}

	if *filterEndTimeStr != "" {
		filterEndTime, err = time.Parse(time.RFC3339, *filterEndTimeStr)
		if err != nil {
			logger.LogError("parsing filter-end-time: %v", err)
			os.Exit(1)
		}
	}

	// Start CPU profiling if requested
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			logger.LogError("creating CPU profile file: %v", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			logger.LogError("starting CPU profile: %v", err)
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}

	// Add 128MB ballast to reduce GC pressure during processing
	ballast := make([]byte, 128*1024*1024)
	_ = ballast

	var logFiles []string

	for _, arg := range *inputs {
		if isDirectory(arg) {
			files, err := FindLogFiles(arg)
			if err != nil {
				logger.LogError("finding log files in directory %s: %v", arg, err)
				continue
			}
			logFiles = append(logFiles, files...)
		} else {
			logFiles = append(logFiles, arg)
		}
	}

	if len(logFiles) == 0 {
		logger.LogError("No log files found")
		os.Exit(1)
	}

	// Trim NAT gateway IPs.
	trimmedNatGatewayIPs := make([]string, len(awsNatGatewayIPs))
	for i, ip := range awsNatGatewayIPs {
		trimmedNatGatewayIPs[i] = strings.TrimSpace(ip)
	}

	// Trim cluster names.
	trimmedClusters := make([]string, len(clusters))
	for i, cluster := range clusters {
		trimmedClusters[i] = strings.TrimSpace(cluster)
	}

	// Parse load balancer target ports.
	var loadBalancerPorts []int
	for _, portStr := range autoDetectLoadBalancerTargetPorts {
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil {
			logger.LogError("invalid port in --auto-detect-load-balancer-target-ports: %s", portStr)
			os.Exit(1)
		}
		loadBalancerPorts = append(loadBalancerPorts, port)
	}

	// Create static service mapper.
	staticMapper, err := NewStaticServiceMapper(*configFile)
	if err != nil {
		logger.LogError("loading config: %v", err)
		os.Exit(1)
	}

	// Create dynamic service mapper.
	dynamicMapper := NewDynamicServiceMapper(logger)

	// Create persistent cache for service mapper.
	cacheDBPath, err := resolveCacheDBPath(*cacheDir)
	if err != nil {
		logger.LogError("resolving cache directory: %v", err)
		os.Exit(1)
	}
	persistentCache := NewServiceMapperPersistentCache(cacheDBPath)
	defer persistentCache.Close()

	serviceMapper := NewServiceMapper(staticMapper, dynamicMapper, persistentCache, logger)

	// Create reader factory based on log type.
	readerFactory, err := NewReaderFactory(*logType)
	if err != nil {
		logger.LogError("creating reader factory: %v", err)
		os.Exit(1)
	}

	analyzer := NewAnalyzer(logFiles, trimmedNatGatewayIPs, filterStartTime, filterEndTime, readerFactory, *autoDetectLoadBalancerFlows, loadBalancerPorts, logger)

	// Process all files
	err = analyzer.Run()
	if err != nil {
		logger.LogError("processing files: %v", err)
		os.Exit(1)
	}

	// Get timestamp range from analyzer in UTC.
	startTime := analyzer.GetStartTime().UTC()
	endTime := analyzer.GetEndTime().UTC()

	// Load pod IP mappings if a Prometheus-compatible API is configured.
	if *mimirURL != "" {
		promClient, err := NewPrometheusClient(*mimirURL, *mimirUsername, *mimirPassword)
		if err != nil {
			logger.LogError("creating Prometheus-compatible API client: %v", err)
			os.Exit(1)
		}

		// Load Kubernetes IP to namespace mappings.
		err = dynamicMapper.LoadKubernetesServiceNames(promClient, trimmedClusters, startTime, endTime)
		if err != nil {
			logger.LogError("loading Kubernetes IP mappings: %v", err)
			// Don't exit on error, just log and continue without Kubernetes IP mappings
		}
	}

	// Resolve service names after processing.
	analyzer.ResolveServiceNames(serviceMapper)

	// Remove excluded endpoints by service name regexp.
	if *excludeEndpointServiceNamesRegexp != "" {
		err = analyzer.RemoveEndpointsByServiceNameRegexp(*excludeEndpointServiceNamesRegexp)
		if err != nil {
			logger.LogError("removing endpoints by service name regexp: %v", err)
			os.Exit(1)
		}
	}

	// Remove excluded sources by service name regexp.
	if *excludeSourceServiceNamesRegexp != "" {
		err = analyzer.RemoveSourcesByServiceNameRegexp(*excludeSourceServiceNamesRegexp)
		if err != nil {
			logger.LogError("removing sources by service name regexp: %v", err)
			os.Exit(1)
		}
	}

	services := analyzer.GetEndpointServicesByBytes()
	totalBytes := analyzer.GetTotalBytes()

	fmt.Printf("\n\nTRAFFIC ANALYSIS REPORT\n-----------------------\n")
	fmt.Printf("Data Period: %s - %s (UTC) (%v)\n\n", startTime.Format("2006-01-02 15:04:05"), endTime.Format("2006-01-02 15:04:05"), endTime.Sub(startTime))
	printEndpointServices(os.Stdout, services, totalBytes, *showDetails, *maxSourcesPerEndpoint, *maxEndpoints)

	sources := analyzer.GetSourceServicesByBytes()
	printSourceServices(os.Stdout, sources, totalBytes, *showDetails, *maxEndpointsPerSource, *maxSources)

	// Write memory profile if requested
	if *memProfile != "" {
		f, err := os.Create(*memProfile)
		if err != nil {
			logger.LogError("creating memory profile file: %v", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := pprof.WriteHeapProfile(f); err != nil {
			logger.LogError("writing memory profile: %v", err)
			os.Exit(1)
		}
	}
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func printEndpointServices(w io.Writer, services []*EndpointService, totalBytes int64, showDetails bool, maxSourcesPerEndpoint int, maxEndpoints int) {
	printServices(w, "Endpoints", "Sources", services, totalBytes, showDetails, maxSourcesPerEndpoint, maxEndpoints, func(s *EndpointService) []*Source { return s.GetSourcesByBytesDesc() })
}

func printSourceServices(w io.Writer, sources []*SourceService, totalBytes int64, showDetails bool, maxEndpointsPerSource int, maxSources int) {
	printServices(w, "Sources", "Endpoints", sources, totalBytes, showDetails, maxEndpointsPerSource, maxSources, func(s *SourceService) []*Endpoint { return s.GetEndpointsByBytesDesc() })
}

func printServices[Services ~[]S, S NameBytesGetter, Details ~[]E, E NameBytesGetter](w io.Writer, title, detailsTitle string, services Services, totalBytes int64, showDetails bool, maxDetailsDisplayCount int, maxDisplayCount int, getDetails func(S) Details) {
	fmt.Fprintf(w, "Top %d %s by Data Transfer:\n\n", maxDisplayCount, title)

	const format = "%2d. %-*s %15.2f MB (%5.2f%%)\n"

	// Sources are already sorted by bytes from GetSourceServicesByBytes
	displayCount := getDisplayCount(services, maxDisplayCount)

	// Find the longest service name (including "Others" if it will be
	// displayed). Use at least 20 characters for readability.
	maxLen := max(lenLongestName(services, displayCount), 20)

	// Print the top N sources.
	for i := range displayCount {
		sourceBytes := services[i].GetBytes()
		mb, pct := mbAndPct(sourceBytes, totalBytes)
		fmt.Fprintf(w, format, i+1, maxLen, services[i].GetName(), mb, pct)

		// Show top endpoints if requested.
		if showDetails {
			printDetails(w, detailsTitle, getDetails(services[i]), sourceBytes, maxDetailsDisplayCount)
		}
	}

	// Add "Others" entry for remaining sources
	if othersBytes := getOthersBytes(services, displayCount); othersBytes > 0 {
		mb, percentage := mbAndPct(othersBytes, totalBytes)
		fmt.Fprintf(w, format, displayCount+1, maxLen, "Others", mb, percentage)
	}
	fmt.Fprintf(w, "\n")
}

func printDetails[Slice ~[]E, E NameBytesGetter](w io.Writer, title string, elements Slice, totalBytes int64, maxDisplayCount int) {
	if len(elements) == 0 {
		return
	}

	const format = "      %2d. %-*s %10.2f MB (%5.2f%%)\n"

	displayCount := getDisplayCount(elements, maxDisplayCount)

	// Get the maximum endpoint name length for this source service
	maxLen := max(lenLongestName(elements, displayCount), 20)

	fmt.Fprintf(w, "    Top %s:\n", strings.ToLower(title))
	for j := range displayCount {
		el := elements[j]
		mb, pct := mbAndPct(el.GetBytes(), totalBytes)
		fmt.Fprintf(w, format, j+1, maxLen, el.GetName(), mb, pct)
	}

	// Add "Others" entry for remaining endpoints
	if othersBytes := getOthersBytes(elements, displayCount); othersBytes > 0 {
		mb, pct := mbAndPct(othersBytes, totalBytes)
		fmt.Fprintf(w, format, displayCount+1, maxLen, "Others", mb, pct)
	}
}

// resolveCacheDBPath returns the full path to the persistent cache SQLite file,
// creating the parent directory if it does not exist. If cacheDir is empty it
// defaults to $XDG_CACHE_HOME/vpc-flow-logs-analyzer (or ~/.cache/vpc-flow-logs-analyzer
// if unset, via os.UserCacheDir).
func resolveCacheDBPath(cacheDir string) (string, error) {
	dir := cacheDir
	if dir == "" {
		userCacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("determining user cache dir: %w", err)
		}
		dir = filepath.Join(userCacheDir, "vpc-flow-logs-analyzer")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating cache dir %q: %w", dir, err)
	}

	return filepath.Join(dir, "service_mapper_cache.db"), nil
}
