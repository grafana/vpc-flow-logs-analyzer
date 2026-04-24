package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.1.100", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
		{"172.15.1.1", false},
		{"172.32.1.1", false},
		{"invalid", false},
		{"", false},
		{"127.0.0.1", true},
		{"2001:db8::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := isPrivateIP(tt.ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// setupTestServiceMapper creates a ServiceMapper with a clean in-memory test database.
func setupTestServiceMapper(t *testing.T, config *StaticServiceMapper) *ServiceMapper {
	// Create new persistent cache and service mapper
	persistentCache := NewServiceMapperPersistentCache(":memory:")
	logger := NewNoopLogger()

	// Create static and dynamic service mappers
	staticMapper := config
	dynamicMapper := NewDynamicServiceMapper(logger)
	serviceMapper := NewServiceMapper(staticMapper, dynamicMapper, persistentCache, logger)

	// Register cleanup function
	t.Cleanup(func() {
		persistentCache.Close()
	})

	return serviceMapper
}
