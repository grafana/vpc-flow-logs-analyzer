package main

import (
	"fmt"
	"net"
	"os"

	"github.com/yl2chen/cidranger"
	"gopkg.in/yaml.v3"
)

// StaticServiceMapperConfig holds configuration for resource name mapping loaded from YAML.
type StaticServiceMapperConfig struct {
	// ResourceNames maps resource names to their associated IP addresses and CIDRs.
	// Key: resource name (e.g., "web-servers", "database-cluster").
	// Value: array of IP addresses or CIDR ranges belonging to that resource.
	ResourceNames map[string][]string `yaml:"resource_names"`
}

// StaticServiceMapper holds optimized data structures for fast IP and CIDR lookup.
type StaticServiceMapper struct {
	// ipToService maps individual IP addresses to service names for fast exact lookup.
	ipToService map[string]string
	// cidrRanger handles CIDR range lookups efficiently.
	cidrRanger cidranger.Ranger
}

// ServiceEntry represents a CIDR range with its associated service name.
type ServiceEntry struct {
	serviceName string
	network     net.IPNet
}

// Network returns the network for this service entry.
func (s *ServiceEntry) Network() net.IPNet {
	return s.network
}

// NewStaticServiceMapper loads configuration from a YAML file or returns empty config if path is empty.
func NewStaticServiceMapper(configPath string) (*StaticServiceMapper, error) {
	var configData StaticServiceMapperConfig

	if configPath == "" {
		configData = StaticServiceMapperConfig{
			ResourceNames: make(map[string][]string),
		}
	} else {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, &configData); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}

		if configData.ResourceNames == nil {
			configData.ResourceNames = make(map[string][]string)
		}
	}

	// Create the StaticServiceMapper with optimized data structures.
	mapper := &StaticServiceMapper{
		ipToService: make(map[string]string),
		cidrRanger:  cidranger.NewPCTrieRanger(),
	}

	// Populate the data structures from config.
	for serviceName, addresses := range configData.ResourceNames {
		for _, addr := range addresses {
			// Check if it's a CIDR range.
			if _, ipNet, err := net.ParseCIDR(addr); err == nil {
				// It's a CIDR, add to ranger.
				entry := &ServiceEntry{
					serviceName: serviceName,
					network:     *ipNet,
				}
				if err := mapper.cidrRanger.Insert(entry); err != nil {
					return nil, fmt.Errorf("failed to insert CIDR %s: %w", addr, err)
				}
			} else {
				// It's an IP address, add to direct lookup map.
				if net.ParseIP(addr) != nil {
					mapper.ipToService[addr] = serviceName
				} else {
					return nil, fmt.Errorf("invalid IP address or CIDR: %s", addr)
				}
			}
		}
	}

	return mapper, nil
}

// GetServiceNameByAddr returns the resource name for a given IP address or empty string if not found.
func (c *StaticServiceMapper) GetServiceNameByAddr(ip string) string {
	// Check exact IP match first (faster).
	if serviceName, exists := c.ipToService[ip]; exists {
		return serviceName
	}

	// Check CIDR ranges.
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	entries, err := c.cidrRanger.ContainingNetworks(parsedIP)
	if err != nil || len(entries) == 0 {
		return ""
	}

	// Return the first matching service name.
	if serviceEntry, ok := entries[0].(*ServiceEntry); ok {
		return serviceEntry.serviceName
	}

	return ""
}
