# VPC Flow Logs Analyzer

A command-line tool that analyzes AWS, GCP, and Azure VPC flow logs to provide insights into network traffic patterns and data transfer costs. This tool helps DevOps teams understand which services are consuming the most bandwidth, identify optimization opportunities, and track network communication patterns across cloud infrastructure.

## How it works

The VPC Flow Logs Analyzer processes raw AWS, GCP, and Azure VPC flow logs and transforms them into actionable insights by:

- **Identifying Top Data Consumers**: Shows which services and endpoints are generating the most network traffic, ranked by data transfer volume
- **Mapping IPs to Services**: Automatically resolves IP addresses to meaningful service names using multiple methods:
  - Static configuration for known cloud resources (AWS, GCP, Azure)
  - Dynamic HTTPS probing for public IPs to detect services by certificates and headers
  - Kubernetes pod IP resolution via Prometheus-compatible API (e.g. Mimir)
- **Source Analysis**: Breaks down where traffic is coming from for each destination service
- **Cost Optimization**: Helps identify expensive data transfer patterns for cloud cost optimization
- **Traffic Deduplication**: Prevents double-counting of data transfer through NAT gateways by filtering out internal routing

### AWS VPC flow logs analysis

Requirements:

- The AWS VPC flow logs are attached to ENIs to AWS NATGateway(s)
- The AWS AWS flow logs format is configured to:
  ```
  version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status pkt-srcaddr pkt-dstaddr pkt-src-aws-service pkt-dst-aws-service
  ```
- The private IP addresses of AWS NATGateway(s) are specified using the CLI flag `--aws-natgateway-ips`

### GCP VPC flow logs analysis

Contrary to AWS, GCP VPC flow logs can't be attached to CloudNAT network interface(s). This means that it's not possible
to isolate the data transfer going through CloudNAT, and this tool uses few tricks to guess it and exclude data transfer
that presumably doesn't go through CloudNAT:

- Data transfer to/from intra-region LBs is excluded when the following CLI flags are configured:
  ```
  # Enable automatic detection of load balancer flows.
  --auto-detect-load-balancer-flows

  # Comma-separated list of ports to consider as load balancer target ports.
  --auto-detect-load-balancer-target-ports=80,443,8000
  ```
- Data transfer to/from GCS (any region) can be excluded by setting:
  ```
  # It's not possible to exclude data transfer to/from GCS in the same region only, because it's not possible to
  # detect the GCS region from flow logs or GCP IPs. For this reason, we recommend to exclude all GCS data transfer
  # from the analysis, assuming most of it is to/from the same region.
  --exclude-endpoint-service-names-regexp='Google Cloud Storage'
  ```
- Data transfer to/from K8S nodes with public networking can be excluded by setting:
  ```
  --exclude-source-service-names-regexp='.*-public-.*'
  ```

## Setup and Usage

### 1. Download VPC flow logs

#### AWS

```bash
# Download all flow logs from S3.
aws --profile my-aws-profile s3 sync --size-only s3://my-cluster-flow-logs ./logs/my-cluster-flow-logs

# Download logs for a specific date only.
aws --profile my-aws-profile s3 sync --size-only --exclude '*' --include '*/2025/08/12/*' s3://my-cluster-flow-logs ./logs/my-cluster-flow-logs
```

#### GCP

```bash
# Download flow logs from GCS (folder).
export GCS_PATH="compute.googleapis.com/vpc_flows/2025/08/15/" && \
mkdir -p "./logs/my-cluster-flow-logs/${GCS_PATH}" && \
gsutil -m rsync -r "gs://my-cluster-flow-logs/${GCS_PATH}" "./logs/my-cluster-flow-logs/${GCS_PATH}"

# Download a single file.
gsutil -m cp "gs://my-cluster-flow-logs/compute.googleapis.com/vpc_flows/2025/08/15/18*" ./logs/
```

#### Azure

```bash
# Download VNet flow logs from Azure Blob Storage.
az storage blob download-batch \
  --account-name mystorageaccount \
  --destination ./logs/my-cluster-flow-logs \
  --source insights-logs-flowlogflowevent
```

### 2. Generate the resource names mapping config file

The tool can resolve IPs to human-readable service names using a static YAML config. Helper scripts are provided to generate these configs from your cloud provider APIs.

```bash
# Generate AWS resources (load balancers, EC2 instances)
./scripts/generate-aws-resource-names-config.sh my-aws-profile us-east-1,eu-west-1 > config-aws.yaml

# Generate AWS IP range mappings (S3, CloudFront, EC2, etc.)
./scripts/generate-aws-services-mapping.sh > config-aws-services.yaml

# Generate GCP resources (load balancers, forwarding rules, Cloud SQL)
./scripts/generate-gcp-resource-names-config.sh my-gcp-project us-central1,europe-west1 > config-gcp.yaml

# Generate Azure resources (load balancers, public IPs)
# To find subscriptions: az account list --query "[].{Name:name, SubscriptionId:id}" --output table
./scripts/generate-azure-resource-names-config.sh 00000000-0000-0000-0000-000000000000 westeurope > config-azure.yaml

# Merge config files
yq eval-all '. as $item ireduce ({}; . * $item)' config-aws.yaml config-aws-services.yaml config-gcp.yaml config-azure.yaml > config.yaml
```

### 3. Run the Analyzer

#### AWS example

```bash
go run . --config=config.yaml \
    --cluster=my-cluster \
    --aws-natgateway-ips=10.0.1.1,10.0.2.1 \
    --mimir-url=https://prometheus.example.com/prometheus \
    --mimir-username=$PROMETHEUS_USER \
    --mimir-password=$PROMETHEUS_PASS \
    --show-details \
    ./logs/my-cluster-flow-logs/
```

#### GCP example

```bash
go run . --config=config.yaml \
    --log-type=gcp \
    --cluster=my-cluster \
    --auto-detect-load-balancer-flows \
    --exclude-endpoint-service-names-regexp='Google Cloud Storage' \
    --exclude-source-service-names-regexp='.*-public-.*' \
    --mimir-url=https://prometheus.example.com/prometheus \
    --mimir-username=$PROMETHEUS_USER \
    --mimir-password=$PROMETHEUS_PASS \
    --show-details \
    ./logs/my-cluster-flow-logs/compute.googleapis.com/vpc_flows/2025/08/15/
```

#### Azure example

```bash
go run . --config=config.yaml \
    --cluster=my-cluster \
    --log-type=azure \
    --mimir-url=https://prometheus.example.com/prometheus \
    --mimir-username=$PROMETHEUS_USER \
    --mimir-password=$PROMETHEUS_PASS \
    --show-details \
    ./logs/my-cluster-flow-logs/
```

### Why NAT Gateway IPs are Required (AWS)

When analyzing VPC flow logs, traffic that goes through NAT gateways appears twice in the logs:
1. **Internal traffic**: From private instance -> NAT gateway (using private IPs)
2. **External traffic**: From NAT gateway -> internet destination (using NAT gateway's public IP)

Without filtering NAT gateway IPs, the same data transfer would be counted twice, leading to inflated bandwidth calculations. By specifying `--aws-natgateway-ips`, the tool excludes the internal routing portion and only counts the actual external data transfer.

### Kubernetes IP resolution

The tool can resolve private IPs to Kubernetes pod names, node names, and service endpoints by querying a Prometheus-compatible API. It queries `kube_pod_info`, `kube_node_info`, and `kube_endpoint_address` metrics, filtering by the cluster name(s) specified with `--cluster`.

Configure with:
- `--mimir-url` - Prometheus-compatible API URL (e.g. `https://prometheus.example.com/prometheus`)
- `--mimir-username` / `--mimir-password` - HTTP basic auth credentials (optional)
- `--cluster` - Comma-separated list of Kubernetes cluster names to match against the `cluster` label in metrics
