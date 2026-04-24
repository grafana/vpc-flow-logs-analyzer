#!/bin/bash

# Script to get Azure Load Balancer names and their IP addresses
# Usage: ./generate-azure-resource-names-config.sh <subscription-id> <comma-separated-regions>

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <subscription-id> <comma-separated-regions>"
    echo "Example: $0 12345678-1234-1234-1234-123456789012 eastus,westus2,westeurope"
    exit 1
fi

SUBSCRIPTION="$1"
REGIONS_STRING="$2"

# Split comma-separated regions into array.
IFS=',' read -ra REGIONS <<< "$REGIONS_STRING"

echo "resource_names:"

# Process each region
for REGION in "${REGIONS[@]}"; do
    # Get all resource groups in this region
    az group list \
        --subscription "$SUBSCRIPTION" \
        --query "[?location=='$REGION'].name" \
        --output tsv | while read -r RG; do

        if [ -n "$RG" ]; then
            # Get load balancers and their IP addresses
            az network lb list \
                --subscription "$SUBSCRIPTION" \
                --resource-group "$RG" \
                --query '[].{Name:name,FrontendConfigs:frontendIPConfigurations}' \
                --output json | jq -r '.[] | .Name as $name | .FrontendConfigs[]? | select(.publicIPAddress) | "\($name)|\(.publicIPAddress.id)"' | while IFS='|' read -r name pip_id; do

                if [ -n "$pip_id" ]; then
                    # Extract resource group and IP name from the resource ID
                    pip_rg=$(echo "$pip_id" | cut -d'/' -f5)
                    pip_name=$(echo "$pip_id" | cut -d'/' -f9)

                    # Get the actual IP address
                    ip=$(az network public-ip show --subscription "$SUBSCRIPTION" --resource-group "$pip_rg" --name "$pip_name" --query 'ipAddress' --output tsv 2>/dev/null)

                    if [ -n "$ip" ] && [ "$ip" != "null" ]; then
                        echo "  \"LB: $name (Azure $REGION)\":"
                        echo "    - \"$ip\""
                    fi
                fi
            done

            # Get Application Gateways and their IP addresses
            az network application-gateway list \
                --subscription "$SUBSCRIPTION" \
                --resource-group "$RG" \
                --query '[].{Name:name,FrontendConfigs:frontendIPConfigurations}' \
                --output json | jq -r '.[] | .Name as $name | .FrontendConfigs[]? | select(.publicIPAddress) | "\($name)|\(.publicIPAddress.id)"' | while IFS='|' read -r name pip_id; do

                if [ -n "$pip_id" ]; then
                    # Extract resource group and IP name from the resource ID
                    pip_rg=$(echo "$pip_id" | cut -d'/' -f5)
                    pip_name=$(echo "$pip_id" | cut -d'/' -f9)

                    # Get the actual IP address
                    ip=$(az network public-ip show --subscription "$SUBSCRIPTION" --resource-group "$pip_rg" --name "$pip_name" --query 'ipAddress' --output tsv 2>/dev/null)

                    if [ -n "$ip" ] && [ "$ip" != "null" ]; then
                        echo "  \"LB: $name (Azure $REGION)\":"
                        echo "    - \"$ip\""
                    fi
                fi
            done

            # Get standalone Public IP addresses
            az network public-ip list \
                --subscription "$SUBSCRIPTION" \
                --resource-group "$RG" \
                --query '[].{Name:name,IpAddress:ipAddress}' \
                --output json | jq -r '.[] | "\(.Name)|\(.IpAddress // empty)"' | while IFS='|' read -r name ip; do

                if [ -n "$ip" ] && [ "$ip" != "null" ]; then
                    echo "  \"IP: $name (Azure $REGION)\":"
                    echo "    - \"$ip\""
                fi
            done
        fi
    done
done
