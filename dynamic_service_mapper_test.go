package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// MockPrometheusClient implements a mock PrometheusClient for testing.
type MockPrometheusClient struct {
	namespaceToIPs map[string][]string
	shouldError    bool
}

// GetUniquePodIPsByNamespace returns the mocked namespace to IP mappings.
func (m *MockPrometheusClient) GetUniquePodIPsByNamespace(ctx context.Context, clusters []string, startTime, endTime time.Time) (map[string][]string, error) {
	if m.shouldError {
		return nil, assert.AnError
	}
	return m.namespaceToIPs, nil
}

// GetUniqueKubernetesEndpointIPsByNamespace returns the mocked namespace to IP mappings for endpoints.
func (m *MockPrometheusClient) GetUniqueKubernetesEndpointIPsByNamespace(ctx context.Context, clusters []string, startTime, endTime time.Time) (map[string][]string, error) {
	if m.shouldError {
		return nil, assert.AnError
	}
	return m.namespaceToIPs, nil
}

// GetUniqueKubernetesNodeIPsByNodeName returns the mocked node name to IP mappings.
func (m *MockPrometheusClient) GetUniqueKubernetesNodeIPsByNodeName(ctx context.Context, clusters []string, startTime, endTime time.Time) (map[string][]string, error) {
	if m.shouldError {
		return nil, assert.AnError
	}
	return m.namespaceToIPs, nil
}

func TestDynamicServiceMapperLoadKubernetesServiceNames(t *testing.T) {
	t.Run("successful load", func(t *testing.T) {
		logger := NewNoopLogger()
		mapper := NewDynamicServiceMapper(logger)

		mockClient := &MockPrometheusClient{
			namespaceToIPs: map[string][]string{
				"web-namespace": {"10.1.1.1", "10.1.1.2"},
				"api-namespace": {"10.2.1.1"},
				"db-namespace":  {"10.3.1.1", "10.3.1.2", "10.3.1.3"},
			},
			shouldError: false,
		}

		startTime := time.Now().Add(-1 * time.Hour)
		endTime := time.Now()

		err := mapper.LoadKubernetesServiceNames(mockClient, []string{"test-cluster"}, startTime, endTime)
		assert.NoError(t, err)

		// Verify Kubernetes IP to namespace mappings
		assert.Equal(t, "web-namespace", mapper.GetServiceNameByAddr("10.1.1.1"))
		assert.Equal(t, "web-namespace", mapper.GetServiceNameByAddr("10.1.1.2"))
		assert.Equal(t, "api-namespace", mapper.GetServiceNameByAddr("10.2.1.1"))
		assert.Equal(t, "db-namespace", mapper.GetServiceNameByAddr("10.3.1.1"))
		assert.Equal(t, "db-namespace", mapper.GetServiceNameByAddr("10.3.1.2"))
		assert.Equal(t, "db-namespace", mapper.GetServiceNameByAddr("10.3.1.3"))

		// Verify unknown IP returns empty string
		assert.Equal(t, "", mapper.GetServiceNameByAddr("10.4.1.1"))
	})

	t.Run("error from PrometheusClient", func(t *testing.T) {
		logger := NewNoopLogger()
		mapper := NewDynamicServiceMapper(logger)

		mockClient := &MockPrometheusClient{
			shouldError: true,
		}

		startTime := time.Now().Add(-1 * time.Hour)
		endTime := time.Now()

		err := mapper.LoadKubernetesServiceNames(mockClient, []string{"test-cluster"}, startTime, endTime)
		assert.Error(t, err)

		// Verify no mappings were loaded
		assert.Equal(t, "", mapper.GetServiceNameByAddr("10.1.1.1"))
	})

	t.Run("empty response from PrometheusClient", func(t *testing.T) {
		logger := NewNoopLogger()
		mapper := NewDynamicServiceMapper(logger)

		mockClient := &MockPrometheusClient{
			namespaceToIPs: map[string][]string{},
			shouldError:    false,
		}

		startTime := time.Now().Add(-1 * time.Hour)
		endTime := time.Now()

		err := mapper.LoadKubernetesServiceNames(mockClient, []string{"test-cluster"}, startTime, endTime)
		assert.NoError(t, err)

		// Verify no mappings were loaded
		assert.Equal(t, "", mapper.GetServiceNameByAddr("10.1.1.1"))
	})

	t.Run("pod IP takes precedence over HTTPS probing", func(t *testing.T) {
		logger := NewNoopLogger()
		mapper := NewDynamicServiceMapper(logger)

		// Load Kubernetes IP mappings first
		mockClient := &MockPrometheusClient{
			namespaceToIPs: map[string][]string{
				"pod-namespace": {"8.8.8.8"}, // Public IP that's also a Kubernetes IP
			},
			shouldError: false,
		}

		startTime := time.Now().Add(-1 * time.Hour)
		endTime := time.Now()

		err := mapper.LoadKubernetesServiceNames(mockClient, []string{"test-cluster"}, startTime, endTime)
		assert.NoError(t, err)

		// Verify Kubernetes IP mapping takes precedence (won't do HTTPS probing)
		serviceName := mapper.GetServiceNameByAddr("8.8.8.8")
		assert.Equal(t, "pod-namespace", serviceName)
	})
}
