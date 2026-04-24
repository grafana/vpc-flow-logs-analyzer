package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerRun(t *testing.T) {
	t.Run("without time filtering", func(t *testing.T) {
		// NAT Gateway IP (will be excluded from destination traffic).
		natGatewayIP := "10.63.37.34"

		// Create analyzer for test fixture.
		logger := NewNoopLogger()
		readerFactory, _ := NewReaderFactory(LogTypeAWS)
		analyzer := NewAnalyzer([]string{"testdata/aws-flow-logs-10.3.11.57-142.250.185.91.log"}, []string{natGatewayIP}, time.Time{}, time.Time{}, readerFactory, false, []int{80, 443}, logger)

		// Run the analyzer.
		err := analyzer.Run()
		require.NoError(t, err)

		// Get the endpoint flows.
		flows := analyzer.GetEndpoints()

		// Verify we have exactly 1 endpoint.
		assert.Len(t, flows, 1)

		// Test 142.250.185.91 endpoint (public IP).
		endpoint, exists := flows["142.250.185.91"]
		require.True(t, exists)
		assert.Equal(t, "142.250.185.91", endpoint.Addr)

		// Calculate expected bytes from all entries (sum of all 31 entries).
		expectedBytes := int64(737 + 1468 + 1244 + 1062 + 2995 + 1817 + 6115 + 36058 + 1808 + 7195 + 34949 + 12627 + 38733 + 5567 + 9454 + 1755 + 912 + 119099 + 2521 + 195 + 1767 + 102861 + 338 + 375 + 104 + 5322 + 5544 + 3099 + 650 + 2615 + 2987)
		assert.Equal(t, expectedBytes, endpoint.Bytes)

		// Verify we have exactly 1 source.
		assert.Len(t, endpoint.Sources, 1)

		// The source should be 10.3.11.57 (PktPrivateAddr from the logs).
		source, exists := endpoint.Sources["10.3.11.57"]
		require.True(t, exists)
		assert.Equal(t, expectedBytes, source.Bytes)
	})

	t.Run("with time filtering", func(t *testing.T) {
		logger := NewNoopLogger()
		readerFactory, _ := NewReaderFactory(LogTypeAWS)

		// First, run without filtering to get baseline results.
		analyzerBaseline := NewAnalyzer([]string{"testdata/aws-flow-logs-10.3.11.57-142.250.185.91.log"}, []string{}, time.Time{}, time.Time{}, readerFactory, false, []int{80, 443}, logger)
		err := analyzerBaseline.Run()
		require.NoError(t, err)

		baselineBytes := analyzerBaseline.GetTotalBytes()
		require.Greater(t, baselineBytes, int64(0), "Baseline should have some data")

		// Test with a filter that should exclude all entries (future date).
		futureTime := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		analyzerFuture := NewAnalyzer([]string{"testdata/aws-flow-logs-10.3.11.57-142.250.185.91.log"}, []string{}, futureTime, time.Time{}, readerFactory, false, []int{80, 443}, logger)
		err = analyzerFuture.Run()
		require.NoError(t, err)

		futureBytes := analyzerFuture.GetTotalBytes()
		assert.Equal(t, int64(0), futureBytes, "Future filter should exclude all entries")

		// Test with a filter that should exclude all entries (past date).
		pastTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		analyzerPast := NewAnalyzer([]string{"testdata/aws-flow-logs-10.3.11.57-142.250.185.91.log"}, []string{}, time.Time{}, pastTime, readerFactory, false, []int{80, 443}, logger)
		err = analyzerPast.Run()
		require.NoError(t, err)

		pastBytes := analyzerPast.GetTotalBytes()
		assert.Equal(t, int64(0), pastBytes, "Past filter should exclude all entries")

		// Test with a very wide range that should include all entries.
		wideStart := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		wideEnd := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		analyzerWide := NewAnalyzer([]string{"testdata/aws-flow-logs-10.3.11.57-142.250.185.91.log"}, []string{}, wideStart, wideEnd, readerFactory, false, []int{80, 443}, logger)
		err = analyzerWide.Run()
		require.NoError(t, err)

		wideBytes := analyzerWide.GetTotalBytes()
		assert.Equal(t, baselineBytes, wideBytes, "Wide range filter should include all entries")

		// Test with a partial range that includes entries from timestamp 1754322900 to 1754323100.
		// Expected entries: 2521+195+1767+34949+12627+38733+5567+9454+1755+912 = 108480 bytes
		partialStart := time.Unix(1754322900, 0)
		partialEnd := time.Unix(1754323100, 0)
		analyzerPartial := NewAnalyzer([]string{"testdata/aws-flow-logs-10.3.11.57-142.250.185.91.log"}, []string{}, partialStart, partialEnd, readerFactory, false, []int{80, 443}, logger)
		err = analyzerPartial.Run()
		require.NoError(t, err)

		partialBytes := analyzerPartial.GetTotalBytes()
		assert.Equal(t, int64(108480), partialBytes, "Partial filter should include exact calculated bytes")

		// Test that the analyzer's reported time range reflects only the filtered entries.
		// From the filtered entries, the min start time is 1754322875 and max end time is 1754323130.
		partialStartTime := analyzerPartial.GetStartTime()
		partialEndTime := analyzerPartial.GetEndTime()
		assert.Equal(t, int64(1754322875), partialStartTime.Unix(), "Reported start time should be exact min from filtered entries")
		assert.Equal(t, int64(1754323130), partialEndTime.Unix(), "Reported end time should be exact max from filtered entries")
	})
}

func TestAnalyzerGetEndpointServicesByBytes(t *testing.T) {
	// Create temporary config file with test service mapping.
	configContent := `resource_names:
  test-service:
    - "1.2.3.4"
`
	configFile := createTempConfigFile(t, configContent)

	// Create config with a test service mapping.
	config, err := NewStaticServiceMapper(configFile)
	require.NoError(t, err)

	serviceMapper := setupTestServiceMapper(t, config)

	// Create analyzer with the sorting test fixture.
	logger := NewNoopLogger()
	readerFactory, _ := NewReaderFactory(LogTypeAWS)
	analyzer := NewAnalyzer([]string{"testdata/aws-analyzer_sorting_test.log"}, []string{}, time.Time{}, time.Time{}, readerFactory, false, []int{80, 443}, logger)

	// Run the analyzer.
	err = analyzer.Run()
	require.NoError(t, err)

	// Resolve service names first (new requirement).
	analyzer.ResolveServiceNames(serviceMapper)

	// Test GetEndpointServicesByBytes (returns all services sorted by bytes).
	// 1.2.3.4 should be mapped to "test-service", while 5.6.7.8 gets "IP: 5.6.7.8" fallback display name, and 9.10.11.12 gets "IP: 9.10.11.12".
	expected := []*EndpointService{
		{
			Name:  "IP: 5.6.7.8",
			Bytes: 10000,
			Endpoints: []*Endpoint{
				{
					Addr:        "5.6.7.8",
					Bytes:       10000,
					ServiceName: "",
					Sources:     map[string]*Source{"10.1.1.1": {Addr: "10.1.1.1", Bytes: 10000, ServiceName: ""}},
				},
			},
		},
		{
			Name:  "test-service",
			Bytes: 5000,
			Endpoints: []*Endpoint{
				{
					Addr:        "1.2.3.4",
					Bytes:       5000,
					ServiceName: "test-service",
					Sources:     map[string]*Source{"10.1.1.1": {Addr: "10.1.1.1", Bytes: 5000, ServiceName: ""}},
				},
			},
		},
		{
			Name:  "IP: 9.10.11.12",
			Bytes: 2000,
			Endpoints: []*Endpoint{
				{
					Addr:        "9.10.11.12",
					Bytes:       2000,
					ServiceName: "",
					Sources:     map[string]*Source{"10.1.1.1": {Addr: "10.1.1.1", Bytes: 2000, ServiceName: ""}},
				},
			},
		},
	}

	actual := analyzer.GetEndpointServicesByBytes()
	assert.Equal(t, expected, actual)
}

func TestServiceMapperLazyCaching(t *testing.T) {
	// Create temporary config file with test service mapping.
	configContent := `resource_names:
  test-service:
    - "1.2.3.4"
`
	configFile := createTempConfigFile(t, configContent)

	// Create config with a test service mapping.
	config, err := NewStaticServiceMapper(configFile)
	require.NoError(t, err)

	serviceMapper := setupTestServiceMapper(t, config)

	// Initially cache should be empty.
	assert.Equal(t, 0, serviceMapper.GetCacheSize())

	// Look up a mapped IP - should cache the result.
	result1 := serviceMapper.GetServiceNameByAddr("1.2.3.4")
	assert.Equal(t, "test-service", result1)
	assert.Equal(t, 1, serviceMapper.GetCacheSize())

	// Look up the same IP again - should use cache.
	result2 := serviceMapper.GetServiceNameByAddr("1.2.3.4")
	assert.Equal(t, "test-service", result2)
	assert.Equal(t, 1, serviceMapper.GetCacheSize()) // Cache size unchanged

	// Look up an unmapped public IP - should cache the result to avoid repeated HTTP requests.
	result3 := serviceMapper.GetServiceNameByAddr("5.6.7.8")
	assert.Equal(t, "", result3)
	assert.Equal(t, 2, serviceMapper.GetCacheSize()) // Cache size increased (cached negative result)

	// Look up the unmapped IP again - should use cached result.
	result4 := serviceMapper.GetServiceNameByAddr("5.6.7.8")
	assert.Equal(t, "", result4)
	assert.Equal(t, 2, serviceMapper.GetCacheSize()) // Cache size unchanged
}

func TestServiceMapperGetServiceNameByAddrs(t *testing.T) {
	// Create temporary config file with test service mappings.
	configContent := `resource_names:
  web-service:
    - "1.2.3.4"
    - "1.2.3.5"
  db-service:
    - "10.0.0.1"
`
	configFile := createTempConfigFile(t, configContent)

	// Create config with test service mappings.
	config, err := NewStaticServiceMapper(configFile)
	require.NoError(t, err)

	serviceMapper := setupTestServiceMapper(t, config)

	// Test concurrent lookup of multiple addresses.
	addrs := []string{
		"1.2.3.4",  // web-service
		"1.2.3.5",  // web-service
		"10.0.0.1", // db-service
		"8.8.8.8",  // unmapped (fallback)
		"9.9.9.9",  // unmapped (fallback)
	}

	result := serviceMapper.GetServiceNameByAddrs(addrs)

	expected := map[string]string{
		"1.2.3.4":  "web-service",
		"1.2.3.5":  "web-service",
		"10.0.0.1": "db-service",
		"8.8.8.8":  "dns.google",
		"9.9.9.9":  "dns.quad9.net",
	}

	assert.Equal(t, expected, result)

	// Verify that successful lookups were cached.
	assert.Equal(t, 5, serviceMapper.GetCacheSize()) // web-service (2 IPs) + db-service (1 IP) + public IPs (2 IPs)
}

func TestAnalyzerResolveServiceNames(t *testing.T) {
	// Create temporary config file with test service mappings.
	configContent := `resource_names:
  web-service:
    - "1.2.3.4"
    - "5.6.7.8"
  database:
    - "10.0.0.100"
  internal-network:
    - "192.168.1.0/24"
`
	configFile := createTempConfigFile(t, configContent)

	// Create config with test service mappings.
	config, err := NewStaticServiceMapper(configFile)
	require.NoError(t, err)

	serviceMapper := setupTestServiceMapper(t, config)

	// Create analyzer and manually populate endpoints with test data.
	logger := NewNoopLogger()
	readerFactory, _ := NewReaderFactory(LogTypeAWS)
	analyzer := NewAnalyzer([]string{}, []string{}, time.Time{}, time.Time{}, readerFactory, false, []int{80, 443}, logger)

	// Manually create test endpoints with sources.
	analyzer.endpoints = map[string]*Endpoint{
		"1.2.3.4": {
			Addr:        "1.2.3.4", // Should resolve to "web-service"
			Bytes:       1000,
			ServiceName: "", // Initially empty
			Sources: map[string]*Source{
				"192.168.1.10": {
					Addr:        "192.168.1.10", // Should resolve to "internal-network"
					Bytes:       500,
					ServiceName: "", // Initially empty
				},
				"10.0.0.100": {
					Addr:        "10.0.0.100", // Should resolve to "database"
					Bytes:       500,
					ServiceName: "", // Initially empty
				},
			},
		},
		"5.6.7.8": {
			Addr:        "5.6.7.8", // Should resolve to "web-service"
			Bytes:       2000,
			ServiceName: "", // Initially empty
			Sources: map[string]*Source{
				"8.8.8.8": {
					Addr:        "8.8.8.8", // Public IP - should get fallback name
					Bytes:       2000,
					ServiceName: "", // Initially empty
				},
			},
		},
	}

	// Call ResolveServiceNames to populate the ServiceName fields.
	analyzer.ResolveServiceNames(serviceMapper)

	// Verify endpoint service names were resolved correctly.
	assert.Equal(t, "web-service", analyzer.endpoints["1.2.3.4"].ServiceName)
	assert.Equal(t, "web-service", analyzer.endpoints["5.6.7.8"].ServiceName)

	// Verify source service names were resolved correctly.
	assert.Equal(t, "internal-network", analyzer.endpoints["1.2.3.4"].Sources["192.168.1.10"].ServiceName)
	assert.Equal(t, "database", analyzer.endpoints["1.2.3.4"].Sources["10.0.0.100"].ServiceName)
	assert.Equal(t, "dns.google", analyzer.endpoints["5.6.7.8"].Sources["8.8.8.8"].ServiceName)
}

func TestAnalyzerGetSourceServicesByBytes(t *testing.T) {
	testCases := map[string]struct {
		endpoints map[string]*Endpoint
		expected  []*SourceService
	}{
		"basic grouping by source service": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       800, // 500 + 300
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "database"},
						"10.0.1.2": {Addr: "10.0.1.2", Bytes: 300, ServiceName: "cache"},
					},
				},
				"2.2.2.2": {
					Addr:        "2.2.2.2",
					Bytes:       800, // 600 + 200
					ServiceName: "api-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 600, ServiceName: "database"},
						"10.0.1.3": {Addr: "10.0.1.3", Bytes: 200, ServiceName: "auth"},
					},
				},
			},
			expected: []*SourceService{
				{
					Name:  "database",
					Bytes: 1100, // 500 + 600
					Endpoints: []*Endpoint{
						{Addr: "", Bytes: 600, ServiceName: "api-service", Sources: nil}, // Sorted by bytes (highest first)
						{Addr: "", Bytes: 500, ServiceName: "web-service", Sources: nil},
					},
				},
				{
					Name:  "cache",
					Bytes: 300,
					Endpoints: []*Endpoint{
						{Addr: "", Bytes: 300, ServiceName: "web-service", Sources: nil},
					},
				},
				{
					Name:  "auth",
					Bytes: 200,
					Endpoints: []*Endpoint{
						{Addr: "", Bytes: 200, ServiceName: "api-service", Sources: nil},
					},
				},
			},
		},
		"merge endpoints with same service name": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       400, // Equal to source bytes
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 400, ServiceName: "database"},
					},
				},
				"1.1.1.2": {
					Addr:        "1.1.1.2",
					Bytes:       600,           // Equal to source bytes
					ServiceName: "web-service", // Same service name as above
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 600, ServiceName: "database"},
					},
				},
			},
			expected: []*SourceService{
				{
					Name:  "database",
					Bytes: 1000, // 400 + 600
					Endpoints: []*Endpoint{
						{Addr: "", Bytes: 1000, ServiceName: "web-service", Sources: nil}, // Merged into single endpoint
					},
				},
			},
		},
		"fallback to IP address for unknown services": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       500, // Equal to source bytes
					ServiceName: "",  // Empty service name
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: ""}, // Empty service name
					},
				},
			},
			expected: []*SourceService{
				{
					Name:  "IP: 10.0.1.1", // Fallback display name
					Bytes: 500,
					Endpoints: []*Endpoint{
						{Addr: "", Bytes: 500, ServiceName: "IP: 1.1.1.1", Sources: nil}, // Fallback display name
					},
				},
			},
		},
		"multiple sources sorted by bytes": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       1000, // 500 + 300 + 200
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "database"},
						"10.0.1.2": {Addr: "10.0.1.2", Bytes: 300, ServiceName: "cache"},
						"10.0.1.3": {Addr: "10.0.1.3", Bytes: 200, ServiceName: "auth"},
					},
				},
			},
			expected: []*SourceService{
				{
					Name:  "database",
					Bytes: 500,
					Endpoints: []*Endpoint{
						{Addr: "", Bytes: 500, ServiceName: "web-service", Sources: nil},
					},
				},
				{
					Name:  "cache",
					Bytes: 300,
					Endpoints: []*Endpoint{
						{Addr: "", Bytes: 300, ServiceName: "web-service", Sources: nil},
					},
				},
				{
					Name:  "auth",
					Bytes: 200,
					Endpoints: []*Endpoint{
						{Addr: "", Bytes: 200, ServiceName: "web-service", Sources: nil},
					},
				},
			},
		},
		"empty endpoints": {
			endpoints: map[string]*Endpoint{},
			expected:  []*SourceService{},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Create analyzer and set test data.
			logger := NewNoopLogger()
			readerFactory, _ := NewReaderFactory(LogTypeAWS)
			analyzer := NewAnalyzer([]string{}, []string{}, time.Time{}, time.Time{}, readerFactory, false, []int{80, 443}, logger)
			analyzer.endpoints = tc.endpoints

			// Validate test data: ensure each endpoint's bytes equal the sum of its sources' bytes.
			for _, endpoint := range tc.endpoints {
				var sourcesTotal int64
				for _, source := range endpoint.Sources {
					sourcesTotal += source.Bytes
				}
				assert.Equal(t, endpoint.Bytes, sourcesTotal, "Endpoint bytes should equal sum of sources bytes for endpoint %s", endpoint.Addr)
			}

			// Call the method under test.
			actual := analyzer.GetSourceServicesByBytes()

			// Compare results.
			require.Equal(t, len(tc.expected), len(actual), "Number of source services should match")

			for i, expectedService := range tc.expected {
				actualService := actual[i]
				assert.Equal(t, expectedService.Name, actualService.Name, "Source service name should match")
				assert.Equal(t, expectedService.Bytes, actualService.Bytes, "Source service bytes should match")

				require.Equal(t, len(expectedService.Endpoints), len(actualService.Endpoints), "Number of endpoints should match")

				// Sort endpoints by service name for consistent comparison.
				expectedEndpoints := expectedService.Endpoints
				actualEndpoints := actualService.Endpoints

				for j, expectedEndpoint := range expectedEndpoints {
					actualEndpoint := actualEndpoints[j]
					assert.Equal(t, expectedEndpoint.Addr, actualEndpoint.Addr, "Endpoint addr should match (empty)")
					assert.Equal(t, expectedEndpoint.Bytes, actualEndpoint.Bytes, "Endpoint bytes should match")
					assert.Equal(t, expectedEndpoint.ServiceName, actualEndpoint.ServiceName, "Endpoint service name should match")
					assert.Nil(t, actualEndpoint.Sources, "Endpoint sources should be nil")
				}
			}
		})
	}
}

func TestAnalyzerRemoveSourcesByServiceNameRegexp(t *testing.T) {
	tests := map[string]struct {
		endpoints         map[string]*Endpoint
		regexPattern      string
		expectedEndpoints map[string]*Endpoint
		expectError       bool
	}{
		"remove sources matching simple pattern": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       1000, // 500 + 300 + 200
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "database-prod"},
						"10.0.1.2": {Addr: "10.0.1.2", Bytes: 300, ServiceName: "database-test"},
						"10.0.1.3": {Addr: "10.0.1.3", Bytes: 200, ServiceName: "cache-service"},
					},
				},
			},
			regexPattern: "^database-",
			expectedEndpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       200, // 1000 - 500 - 300 = 200
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.3": {Addr: "10.0.1.3", Bytes: 200, ServiceName: "cache-service"},
					},
				},
			},
		},
		"remove all sources": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       800, // 500 + 300
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "database-prod"},
						"10.0.1.2": {Addr: "10.0.1.2", Bytes: 300, ServiceName: "database-test"},
					},
				},
			},
			regexPattern: "database.*",
			expectedEndpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       0, // All sources removed
					ServiceName: "web-service",
					Sources:     map[string]*Source{},
				},
			},
		},
		"no sources match pattern": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       800, // 500 + 300
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "cache-service"},
						"10.0.1.2": {Addr: "10.0.1.2", Bytes: 300, ServiceName: "auth-service"},
					},
				},
			},
			regexPattern: "^database-",
			expectedEndpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       800, // No change
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "cache-service"},
						"10.0.1.2": {Addr: "10.0.1.2", Bytes: 300, ServiceName: "auth-service"},
					},
				},
			},
		},
		"multiple endpoints": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       600, // 400 + 200
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 400, ServiceName: "test-database"},
						"10.0.1.2": {Addr: "10.0.1.2", Bytes: 200, ServiceName: "cache-service"},
					},
				},
				"2.2.2.2": {
					Addr:        "2.2.2.2",
					Bytes:       500, // 300 + 200
					ServiceName: "api-service",
					Sources: map[string]*Source{
						"10.0.1.3": {Addr: "10.0.1.3", Bytes: 300, ServiceName: "test-auth"},
						"10.0.1.4": {Addr: "10.0.1.4", Bytes: 200, ServiceName: "logging-service"},
					},
				},
			},
			regexPattern: "^test-",
			expectedEndpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       200, // 600 - 400 = 200
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.2": {Addr: "10.0.1.2", Bytes: 200, ServiceName: "cache-service"},
					},
				},
				"2.2.2.2": {
					Addr:        "2.2.2.2",
					Bytes:       200, // 500 - 300 = 200
					ServiceName: "api-service",
					Sources: map[string]*Source{
						"10.0.1.4": {Addr: "10.0.1.4", Bytes: 200, ServiceName: "logging-service"},
					},
				},
			},
		},
		"ensure bytes never go negative": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       100, // Less than source bytes (edge case)
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "database-service"},
					},
				},
			},
			regexPattern: "database.*",
			expectedEndpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       0, // max(100 - 500, 0) = 0
					ServiceName: "web-service",
					Sources:     map[string]*Source{},
				},
			},
		},
		"empty regex pattern": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       500,
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "database-service"},
					},
				},
			},
			regexPattern: "",
			expectedEndpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       500, // No change for empty pattern
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "database-service"},
					},
				},
			},
		},
		"invalid regex pattern": {
			endpoints: map[string]*Endpoint{
				"1.1.1.1": {
					Addr:        "1.1.1.1",
					Bytes:       500,
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 500, ServiceName: "database-service"},
					},
				},
			},
			regexPattern: "[invalid",
			expectError:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Create analyzer and set test data.
			logger := NewNoopLogger()
			readerFactory, _ := NewReaderFactory(LogTypeAWS)
			analyzer := NewAnalyzer([]string{}, []string{}, time.Time{}, time.Time{}, readerFactory, false, []int{80, 443}, logger)
			analyzer.endpoints = tc.endpoints

			// Call the method under test.
			err := analyzer.RemoveSourcesByServiceNameRegexp(tc.regexPattern)

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid regular expression")
			} else {
				assert.NoError(t, err)
				// Compare results.
				assert.Equal(t, tc.expectedEndpoints, analyzer.endpoints)
			}
		})
	}
}
