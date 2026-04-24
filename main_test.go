package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrintEndpointServices(t *testing.T) {
	// Create test data with realistic MB values
	services := []*EndpointService{
		{
			Name:  "web-service",
			Bytes: 15728640, // 15 MB
			Endpoints: []*Endpoint{
				{
					Addr:        "1.2.3.4",
					Bytes:       15728640,
					ServiceName: "web-service",
					Sources: map[string]*Source{
						"10.0.1.1": {Addr: "10.0.1.1", Bytes: 10485760, ServiceName: "database"}, // 10 MB
						"10.0.1.2": {Addr: "10.0.1.2", Bytes: 5242880, ServiceName: "cache"},     // 5 MB
					},
				},
			},
		},
		{
			Name:  "api-service",
			Bytes: 8388608, // 8 MB
			Endpoints: []*Endpoint{
				{
					Addr:        "5.6.7.8",
					Bytes:       8388608,
					ServiceName: "api-service",
					Sources: map[string]*Source{
						"10.0.1.3": {Addr: "10.0.1.3", Bytes: 8388608, ServiceName: "frontend"}, // 8 MB
					},
				},
			},
		},
		{
			Name:  "IP: 9.10.11.12",
			Bytes: 2097152, // 2 MB
			Endpoints: []*Endpoint{
				{
					Addr:        "9.10.11.12",
					Bytes:       2097152,
					ServiceName: "",
					Sources: map[string]*Source{
						"10.0.1.4": {Addr: "10.0.1.4", Bytes: 2097152, ServiceName: ""}, // 2 MB
					},
				},
			},
		},
	}

	totalBytes := int64(26214400) // 25 MB total
	var buf bytes.Buffer

	// Test with showDetails=true, maxSourcesPerEndpoint=2, maxEndpoints=2
	printEndpointServices(&buf, services, totalBytes, true, 2, 2)

	expected := `Top 2 Endpoints by Data Transfer:

 1. web-service                    15.00 MB (60.00%)
    Top sources:
       1. 10.0.1.1 (database)       10.00 MB (66.67%)
       2. 10.0.1.2 (cache)           5.00 MB (33.33%)
 2. api-service                     8.00 MB (32.00%)
    Top sources:
       1. 10.0.1.3 (frontend)        8.00 MB (100.00%)
 3. Others                          2.00 MB ( 8.00%)

`

	assert.Equal(t, expected, buf.String())
}

func TestPrintSourceServices(t *testing.T) {
	// Create test data with realistic MB values
	sources := []*SourceService{
		{
			Name:  "database",
			Bytes: 12582912, // 12 MB
			Endpoints: []*Endpoint{
				{
					Addr:        "",
					Bytes:       8388608, // 8 MB
					ServiceName: "web-service",
					Sources:     nil,
				},
				{
					Addr:        "",
					Bytes:       4194304, // 4 MB
					ServiceName: "api-service",
					Sources:     nil,
				},
			},
		},
		{
			Name:  "frontend",
			Bytes: 7340032, // 7 MB
			Endpoints: []*Endpoint{
				{
					Addr:        "",
					Bytes:       7340032, // 7 MB
					ServiceName: "api-service",
					Sources:     nil,
				},
			},
		},
		{
			Name:  "cache",
			Bytes: 3145728, // 3 MB
			Endpoints: []*Endpoint{
				{
					Addr:        "",
					Bytes:       3145728, // 3 MB
					ServiceName: "web-service",
					Sources:     nil,
				},
			},
		},
	}

	totalBytes := int64(23068672) // 22 MB total
	var buf bytes.Buffer

	// Test with showDetails=true, maxEndpointsPerSource=2, maxSources=2
	printSourceServices(&buf, sources, totalBytes, true, 2, 2)

	expected := `Top 2 Sources by Data Transfer:

 1. database                       12.00 MB (54.55%)
    Top endpoints:
       1. web-service                8.00 MB (66.67%)
       2. api-service                4.00 MB (33.33%)
 2. frontend                        7.00 MB (31.82%)
    Top endpoints:
       1. api-service                7.00 MB (100.00%)
 3. Others                          3.00 MB (13.64%)

`

	assert.Equal(t, expected, buf.String())
}
