package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTempConfigFile creates a temporary config file with the given content and returns the file path.
func createTempConfigFile(t *testing.T, configContent string) string {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_config.yaml")
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)
	return configFile
}

func TestGetServiceNameByAddr(t *testing.T) {
	// Create temporary config file with both IPs and CIDRs.
	configContent := `resource_names:
  web-servers:
    - "10.0.1.100"
    - "10.0.1.101"
    - "10.0.3.0/24"
  database:
    - "10.0.2.50"
    - "192.168.1.0/28"
  load-balancer:
    - "3.20.112.225"
  internal-net:
    - "172.16.0.0/16"
`

	configFile := createTempConfigFile(t, configContent)

	// Load config using NewStaticServiceMapper.
	mapper, err := NewStaticServiceMapper(configFile)
	require.NoError(t, err)
	require.NotNil(t, mapper)

	tests := map[string]struct {
		ip       string
		expected string
	}{
		"IP found in web-servers": {
			ip:       "10.0.1.100",
			expected: "web-servers",
		},
		"IP found in database": {
			ip:       "10.0.2.50",
			expected: "database",
		},
		"IP found in load-balancer": {
			ip:       "3.20.112.225",
			expected: "load-balancer",
		},
		"IP in web-servers CIDR": {
			ip:       "10.0.3.50",
			expected: "web-servers",
		},
		"IP in database CIDR": {
			ip:       "192.168.1.5",
			expected: "database",
		},
		"IP in internal-net CIDR": {
			ip:       "172.16.100.200",
			expected: "internal-net",
		},
		"IP not found should return empty string": {
			ip:       "8.8.8.8",
			expected: "",
		},
		"Empty IP should return empty": {
			ip:       "",
			expected: "",
		},
		"Invalid IP should return empty": {
			ip:       "invalid-ip",
			expected: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := mapper.GetServiceNameByAddr(tc.ip)
			assert.Equal(t, tc.expected, result)
		})
	}
}
