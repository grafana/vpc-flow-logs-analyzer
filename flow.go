package main

import "sort"

type NameGetter interface{ GetName() string }

type BytesGetter interface{ GetBytes() int64 }

type NameBytesGetter interface {
	NameGetter
	BytesGetter
}

// Source holds information about network flow from a specific source.
type Source struct {
	// Addr is the IP address of the source.
	Addr string

	// Bytes is the total number of bytes transferred from this source to the endpoint.
	Bytes int64

	// ServiceName is the resolved service name for this source IP address.
	ServiceName string
}

// GetName returns the address with service name in parentheses if available.
func (s *Source) GetName() string {
	if s.ServiceName != "" {
		return s.Addr + " (" + s.ServiceName + ")"
	}
	return s.Addr
}

func (s *Source) GetBytes() int64 { return s.Bytes }

// Endpoint holds information about network flow to/from a public endpoint or private service endpoint.
type Endpoint struct {
	// Addr is the IP address of the endpoint.
	Addr string

	// Bytes is the total bytes transferred to/from this endpoint.
	Bytes int64

	// ServiceName is the resolved service name for this endpoint IP address.
	ServiceName string

	// Sources maps source IP addresses to their flow information.
	// The key is the IP address from PktPrivateAddr (or PktSrcAddr when PktPrivateAddr is empty).
	Sources map[string]*Source
}

// GetName returns the service name if available, otherwise the IP address.
func (e *Endpoint) GetName() string {
	if e.ServiceName != "" {
		return e.ServiceName
	}
	return e.Addr
}

func (e *Endpoint) GetBytes() int64 { return e.Bytes }

// EndpointService holds information about network flow to/from a service.
type EndpointService struct {
	// Name is the human readable name of the service.
	Name string

	// Bytes is the total bytes transferred to/from this service.
	Bytes int64

	// Endpoints holds all endpoints for this service.
	Endpoints []*Endpoint
}

func (s *EndpointService) GetName() string { return s.Name }
func (s *EndpointService) GetBytes() int64 { return s.Bytes }

// SourceService holds information about network flow from a service acting as a source.
type SourceService struct {
	// Name is the human readable name of the source service.
	Name string

	// Bytes is the total bytes transferred from this source service.
	Bytes int64

	// Endpoints holds all endpoints that this source service sends traffic to.
	Endpoints []*Endpoint
}

func (s *SourceService) GetName() string { return s.Name }
func (s *SourceService) GetBytes() int64 { return s.Bytes }

// GetEndpointsByBytesDesc returns the source service endpoints sorted by bytes in descending order.
func (s *SourceService) GetEndpointsByBytesDesc() []*Endpoint {
	// Endpoints are already sorted by bytes in GetSourceServicesByBytes.
	return s.Endpoints
}

// GetSourcesByBytesDesc returns all sources across service endpoints, merged by Addr and sorted by bytes in descending order.
func (s *EndpointService) GetSourcesByBytesDesc() []*Source {
	// Aggregate sources by address across all endpoints.
	sourceMap := make(map[string]*Source)

	for _, endpoint := range s.Endpoints {
		for _, source := range endpoint.Sources {
			if existingSource, exists := sourceMap[source.Addr]; exists {
				// Merge bytes for existing source.
				existingSource.Bytes += source.Bytes
			} else {
				// Create new aggregated source.
				sourceMap[source.Addr] = &Source{
					Addr:        source.Addr,
					Bytes:       source.Bytes,
					ServiceName: source.ServiceName,
				}
			}
		}
	}

	// Convert map to slice for sorting.
	sources := make([]*Source, 0, len(sourceMap))
	for _, source := range sourceMap {
		sources = append(sources, source)
	}

	// Sort by bytes in descending order, then by address for stable sorting.
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Bytes == sources[j].Bytes {
			return sources[i].Addr < sources[j].Addr
		}
		return sources[i].Bytes > sources[j].Bytes
	})

	return sources
}
