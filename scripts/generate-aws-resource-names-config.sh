#!/bin/bash

# Script to get AWS resource names and their IP addresses (Load Balancers and EC2 instances)
# Usage: ./generate-resource-names-config.sh <aws-profile> <comma-separated-regions>

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <aws-profile> <comma-separated-regions>"
    echo "Example: $0 my-profile us-east-1,us-west-2,eu-west-1"
    exit 1
fi

PROFILE="$1"
REGIONS_STRING="$2"

# Split comma-separated regions into array.
IFS=',' read -ra REGIONS <<< "$REGIONS_STRING"

echo "resource_names:"

for REGION in "${REGIONS[@]}"; do
    # Get load balancers and their IPs
    aws elbv2 describe-load-balancers \
        --region "$REGION" \
        --profile "$PROFILE" \
        --query 'LoadBalancers[].{Name:LoadBalancerName,DNS:DNSName}' \
        --output json | jq -r '.[] | "\(.Name)|\(.DNS)"' | while IFS='|' read -r name dns; do

        # Resolve DNS to IP addresses
        ips=$(dig +short "$dns" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | paste -sd ',' -)

        if [ -n "$ips" ]; then
            # Format for YAML with region prefix
            echo "  \"LB: $name (AWS $REGION)\":"
            echo "$ips" | tr ',' '\n' | while read -r ip; do
                if [ -n "$ip" ]; then
                    echo "    - \"$ip\""
                fi
            done
        fi
    done

    # Get EC2 instances and their IPs
    # shellcheck disable=SC2016
    aws ec2 describe-instances \
        --region "$REGION" \
        --profile "$PROFILE" \
        --query 'Reservations[].Instances[?State.Name==`running`].{Name:Tags[?Key==`Name`]|[0].Value,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress}' \
        --output json | jq -r '.[][] | select(.Name != null) | "\(.Name)|\(.PrivateIp // "")|\(.PublicIp // "")"' | while IFS='|' read -r name private_ip public_ip; do

        # Collect all IPs for this instance
        instance_ips=""
        if [ -n "$private_ip" ]; then
            instance_ips="$private_ip"
        fi
        if [ -n "$public_ip" ]; then
            if [ -n "$instance_ips" ]; then
                instance_ips="$instance_ips,$public_ip"
            else
                instance_ips="$public_ip"
            fi
        fi

        if [ -n "$instance_ips" ]; then
            # Format for YAML with region prefix
            echo "  \"EC2: $name (AWS $REGION)\":"
            echo "$instance_ips" | tr ',' '\n' | while read -r ip; do
                if [ -n "$ip" ]; then
                    echo "    - \"$ip\""
                fi
            done
        fi
    done
done
