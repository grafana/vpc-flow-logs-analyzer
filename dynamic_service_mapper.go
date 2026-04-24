package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

// DynamicServiceMapper maps IP addresses to service names using HTTPS probing and Kubernetes IP lookup.
type DynamicServiceMapper struct {
	logger Logger

	// kubernetesIPToNamespace maps Kubernetes IP addresses (pods and endpoints) to namespaces.
	kubernetesIPToNamespace map[string]string

	// kubernetesIPToNode maps Kubernetes node IP addresses to node names.
	kubernetesIPToNode map[string]string
}

// NewDynamicServiceMapper creates a new DynamicServiceMapper instance with the provided logger.
func NewDynamicServiceMapper(logger Logger) *DynamicServiceMapper {
	return &DynamicServiceMapper{
		logger:                  logger,
		kubernetesIPToNamespace: make(map[string]string),
		kubernetesIPToNode:      make(map[string]string),
	}
}

// KubernetesIPProvider defines the interface for getting Kubernetes IP mappings.
type KubernetesIPProvider interface {
	GetUniquePodIPsByNamespace(ctx context.Context, clusters []string, startTime, endTime time.Time) (map[string][]string, error)
	GetUniqueKubernetesEndpointIPsByNamespace(ctx context.Context, clusters []string, startTime, endTime time.Time) (map[string][]string, error)
	GetUniqueKubernetesNodeIPsByNodeName(ctx context.Context, clusters []string, startTime, endTime time.Time) (map[string][]string, error)
}

// LoadKubernetesServiceNames loads Kubernetes IP to namespace mappings from a KubernetesIPProvider.
func (sm *DynamicServiceMapper) LoadKubernetesServiceNames(provider KubernetesIPProvider, clusters []string, startTime, endTime time.Time) error {
	sm.logger.LogInfo("Loading Kubernetes service names for clusters %s from %v to %v", strings.Join(clusters, ","), startTime, endTime)
	ctx := context.Background()

	// Get pod IP to namespace mappings from provider
	podNamespaceToIPs, err := provider.GetUniquePodIPsByNamespace(ctx, clusters, startTime, endTime)
	if err != nil {
		return err
	}

	// Get endpoint IP to namespace mappings from provider
	endpointNamespaceToIPs, err := provider.GetUniqueKubernetesEndpointIPsByNamespace(ctx, clusters, startTime, endTime)
	if err != nil {
		return err
	}

	// Get node IP to node name mappings from provider
	nodeToIPs, err := provider.GetUniqueKubernetesNodeIPsByNodeName(ctx, clusters, startTime, endTime)
	if err != nil {
		return err
	}

	// Convert pod namespace -> []IP to IP -> namespace mapping
	for namespace, ips := range podNamespaceToIPs {
		for _, ip := range ips {
			sm.kubernetesIPToNamespace[ip] = namespace
		}
	}

	// Convert endpoint namespace -> []IP to IP -> namespace mapping
	for namespace, ips := range endpointNamespaceToIPs {
		for _, ip := range ips {
			sm.kubernetesIPToNamespace[ip] = namespace
		}
	}

	// Convert node name -> []IP to IP -> node name mapping
	for nodeName, ips := range nodeToIPs {
		for _, ip := range ips {
			sm.kubernetesIPToNode[ip] = nodeName
		}
	}

	sm.logger.LogInfo("Loaded %d Kubernetes IP to namespace mappings and %d node IP mappings", len(sm.kubernetesIPToNamespace), len(sm.kubernetesIPToNode))
	return nil
}

// GetServiceNameByAddr returns the service name for a given address using Kubernetes IP lookup first, then HTTPS probing, or empty string if unknown.
func (sm *DynamicServiceMapper) GetServiceNameByAddr(addr string) string {
	// Check node IP mappings first
	if nodeName, exists := sm.kubernetesIPToNode[addr]; exists {
		return nodeName
	}

	// Check Kubernetes IP mappings (for both private and public IPs)
	if serviceName, exists := sm.kubernetesIPToNamespace[addr]; exists {
		return serviceName
	}

	// Only probe public IPs for HTTPS-based detection.
	if !isPrivateIP(addr) {
		return sm.detectServiceNameByHTTPSProbing(addr)
	}

	// Return empty string for private IPs that are not Kubernetes IPs (unknown).
	return ""
}

// detectServiceNameByHTTPSProbing probes an IP address via HTTPS to detect the service based on response headers and TLS certificate.
// Returns the service name or empty string if no known service is detected.
func (sm *DynamicServiceMapper) detectServiceNameByHTTPSProbing(addr string) string {
	// Create HTTP client with TLS verification disabled and 3s timeout.
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Make HTTPS request to the IP address.
	resp, err := client.Get("https://" + addr)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// Check response headers first.
	if _, exists := resp.Header["X-Guploader-Uploadid"]; exists {
		return "Google Cloud Storage"
	}

	if _, exists := resp.Header["X-Kubernetes-Pf-Flowschema-Uid"]; exists {
		return "Kubernetes controlplane"
	}

	if server := resp.Header.Get("Server"); server == "gws" {
		return "Unknown services in GCP"
	}

	// Check TLS certificate if headers didn't match.
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		cn := cert.Subject.CommonName
		if cn != "" {
			return cn
		}
	}

	// No known service detected.
	return ""
}
