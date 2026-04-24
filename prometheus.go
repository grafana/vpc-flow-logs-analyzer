package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	promapi "github.com/prometheus/client_golang/api"
	promv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

// PrometheusClient is a wrapper of github.com/prometheus/client_golang/api.Client.
type PrometheusClient struct {
	api promv1.API
}

// NewPrometheusClient creates a new PrometheusClient with the specified URL and authentication credentials.
func NewPrometheusClient(url, username, password string) (*PrometheusClient, error) {
	apiClient, err := promapi.NewClient(promapi.Config{
		Address: url,
		RoundTripper: &prometheusClientTripper{
			next:         http.DefaultTransport,
			authUsername: username,
			authPassword: password,
		},
	})
	if err != nil {
		return nil, err
	}

	return &PrometheusClient{
		api: promv1.NewAPI(apiClient),
	}, nil
}

// Query executes a PromQL query at the specified time.
func (c *PrometheusClient) Query(ctx context.Context, query string, ts time.Time, opts ...promv1.Option) (model.Value, promv1.Warnings, error) {
	return c.api.Query(ctx, query, ts, opts...)
}

// getUniqueIPsByGroupingLabel is a common function that queries Kubernetes metrics for IP addresses by grouping label.
func (c *PrometheusClient) getUniqueIPsByGroupingLabel(ctx context.Context, query string, endTime time.Time, ipLabelName, groupLabelName string) (map[string][]string, error) {
	// Execute the instant query at endTime
	result, _, err := c.api.Query(ctx, query, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to execute PromQL query: %w", err)
	}

	// The result should be a vector
	vector, ok := result.(model.Vector)
	if !ok {
		return nil, fmt.Errorf("unexpected result type: expected Vector, got %T", result)
	}

	// First pass: collect all IP -> group mappings
	ipToGroups := make(map[string][]string)
	for _, sample := range vector {
		ip := string(sample.Metric[model.LabelName(ipLabelName)])
		group := string(sample.Metric[model.LabelName(groupLabelName)])

		if ip != "" && group != "" {
			ipToGroups[ip] = append(ipToGroups[ip], group)
		}
	}

	// Second pass: build group -> IPs map, excluding IPs that appear in multiple groups
	groupToIPs := make(map[string][]string)
	for ip, groups := range ipToGroups {
		if len(groups) == 1 {
			group := groups[0]
			groupToIPs[group] = append(groupToIPs[group], ip)
		}
		// Skip IPs that appear in more than 1 group
	}

	return groupToIPs, nil
}

// GetUniquePodIPsByNamespace returns a map of namespace to list of unique pod IPs for the specified clusters.
// Pod IPs that appear in multiple namespaces are excluded from the result.
func (c *PrometheusClient) GetUniquePodIPsByNamespace(ctx context.Context, clusters []string, startTime, endTime time.Time) (map[string][]string, error) {
	// Calculate duration for the query
	duration := endTime.Sub(startTime)

	// Build cluster regex from list of clusters
	clusterRegex := strings.Join(clusters, "|")

	// Build the PromQL query using regex to match all clusters
	query := fmt.Sprintf(`count by(pod_ip, namespace) (
        max_over_time(kube_pod_info{cluster=~"%s"}[%s])
    )`, clusterRegex, duration.String())

	return c.getUniqueIPsByGroupingLabel(ctx, query, endTime, "pod_ip", "namespace")
}

// GetUniqueKubernetesNodeIPsByNodeName returns a map of node name to list of unique node internal IPs for the specified clusters.
// Node IPs that appear in multiple nodes are excluded from the result.
func (c *PrometheusClient) GetUniqueKubernetesNodeIPsByNodeName(ctx context.Context, clusters []string, startTime, endTime time.Time) (map[string][]string, error) {
	// Calculate duration for the query
	duration := endTime.Sub(startTime)

	// Build cluster regex from list of clusters
	clusterRegex := strings.Join(clusters, "|")

	// Build the PromQL query using regex to match all clusters
	query := fmt.Sprintf(`count by(internal_ip, node) (
        max_over_time(kube_node_info{cluster=~"%s"}[%s])
    )`, clusterRegex, duration.String())

	return c.getUniqueIPsByGroupingLabel(ctx, query, endTime, "internal_ip", "node")
}

// GetUniqueKubernetesEndpointIPsByNamespace returns a map of namespace to list of unique endpoint IPs for the specified clusters.
// Endpoint IPs that appear in multiple namespaces are excluded from the result.
func (c *PrometheusClient) GetUniqueKubernetesEndpointIPsByNamespace(ctx context.Context, clusters []string, startTime, endTime time.Time) (map[string][]string, error) {
	// Calculate duration for the query
	duration := endTime.Sub(startTime)

	// Build cluster regex from list of clusters
	clusterRegex := strings.Join(clusters, "|")

	// Build the PromQL query using regex to match all clusters
	query := fmt.Sprintf(`count by(ip, namespace) (
        max_over_time(kube_endpoint_address{cluster=~"%s"}[%s])
    )`, clusterRegex, duration.String())

	return c.getUniqueIPsByGroupingLabel(ctx, query, endTime, "ip", "namespace")
}

// prometheusClientTripper is a custom RoundTripper that adds HTTP basic authentication and user agent.
type prometheusClientTripper struct {
	next http.RoundTripper

	authUsername string
	authPassword string
}

// RoundTrip implements http.RoundTripper interface.
func (r *prometheusClientTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.authUsername != "" && r.authPassword != "" {
		req.SetBasicAuth(r.authUsername, r.authPassword)
	}

	req.Header.Set("User-Agent", "vpc-flow-logs-analyzer")

	return r.next.RoundTrip(req)
}
