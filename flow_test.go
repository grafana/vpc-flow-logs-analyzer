package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceGetSourcesByBytesDesc(t *testing.T) {
	// Create test service with multiple endpoints that share some sources.
	service := &EndpointService{
		Name:  "Multi-Endpoint Service",
		Bytes: 25000,
		Endpoints: []*Endpoint{
			{
				Addr:  "1.2.3.4",
				Bytes: 8000,
				Sources: map[string]*Source{
					"10.0.0.1": {Addr: "10.0.0.1", Bytes: 5000},
					"10.0.0.2": {Addr: "10.0.0.2", Bytes: 3000},
				},
			},
			{
				Addr:  "5.6.7.8",
				Bytes: 12000,
				Sources: map[string]*Source{
					"10.0.0.1": {Addr: "10.0.0.1", Bytes: 7000}, // Same source as above
					"10.0.0.3": {Addr: "10.0.0.3", Bytes: 5000},
				},
			},
			{
				Addr:  "9.10.11.12",
				Bytes: 5000,
				Sources: map[string]*Source{
					"10.0.0.2": {Addr: "10.0.0.2", Bytes: 2000}, // Same source as first endpoint
					"10.0.0.4": {Addr: "10.0.0.4", Bytes: 3000},
				},
			},
		},
	}

	t.Run("merged sources sorted by bytes", func(t *testing.T) {
		result := service.GetSourcesByBytesDesc()

		// Should return all sources merged by Addr and sorted by bytes desc, then by addr asc.
		// 10.0.0.1: 5000 + 7000 = 12000
		// 10.0.0.2: 3000 + 2000 = 5000
		// 10.0.0.3: 5000
		// 10.0.0.4: 3000
		expected := []*Source{
			{Addr: "10.0.0.1", Bytes: 12000}, // Merged from both endpoints
			{Addr: "10.0.0.2", Bytes: 5000},  // Merged from two endpoints (addr < 10.0.0.3)
			{Addr: "10.0.0.3", Bytes: 5000},  // Only in one endpoint
			{Addr: "10.0.0.4", Bytes: 3000},  // Only in one endpoint
		}

		assert.Equal(t, expected, result)
	})

	t.Run("empty endpoints", func(t *testing.T) {
		emptyService := &EndpointService{
			Name:      "Empty Service",
			Bytes:     0,
			Endpoints: []*Endpoint{},
		}

		result := emptyService.GetSourcesByBytesDesc()
		assert.Empty(t, result)
	})

	t.Run("endpoints with no sources", func(t *testing.T) {
		noSourcesService := &EndpointService{
			Name:  "No Sources Service",
			Bytes: 0,
			Endpoints: []*Endpoint{
				{Addr: "1.1.1.1", Bytes: 0, Sources: map[string]*Source{}},
				{Addr: "2.2.2.2", Bytes: 0, Sources: map[string]*Source{}},
			},
		}

		result := noSourcesService.GetSourcesByBytesDesc()
		assert.Empty(t, result)
	})

	t.Run("single source across multiple endpoints", func(t *testing.T) {
		singleSourceService := &EndpointService{
			Name:  "Single Source Service",
			Bytes: 15000,
			Endpoints: []*Endpoint{
				{
					Addr:  "1.1.1.1",
					Bytes: 10000,
					Sources: map[string]*Source{
						"10.0.0.1": {Addr: "10.0.0.1", Bytes: 10000},
					},
				},
				{
					Addr:  "2.2.2.2",
					Bytes: 5000,
					Sources: map[string]*Source{
						"10.0.0.1": {Addr: "10.0.0.1", Bytes: 5000}, // Same source as above
					},
				},
			},
		}

		result := singleSourceService.GetSourcesByBytesDesc()

		// Should merge the same source across endpoints.
		expected := []*Source{
			{Addr: "10.0.0.1", Bytes: 15000}, // 10000 + 5000
		}

		assert.Equal(t, expected, result)
	})
}
