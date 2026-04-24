#!/bin/bash

# Script to get GCP resource names and their IP addresses (Load Balancers, IP addresses, and Cloud SQL instances)
# Usage: ./generate-gcp-resource-names-config.sh <gcp-project> <comma-separated-regions>

set -e

if [ $# -ne 2 ]; then
	echo "Usage: $0 <gcp-project> <comma-separated-regions>"
	echo "Example: $0 my-gcp-project us-central1,us-east1,europe-west1"
	exit 1
fi

PROJECT="$1"
REGIONS_STRING="$2"

# Split comma-separated regions into array.
IFS=',' read -ra REGIONS <<<"$REGIONS_STRING"

echo "resource_names:"

for REGION in "${REGIONS[@]}"; do
	# Get load balancers (forwarding rules) and their IP addresses
	gcloud compute forwarding-rules list \
		--project="$PROJECT" \
		--regions="$REGION" \
		--format="json" | jq -r '.[] | "\(.name)|\(.IPAddress // empty)"' | while IFS='|' read -r name ip; do

		if [ -n "$ip" ] && [ "$ip" != "null" ]; then
			# Format for YAML with region prefix
			echo "  \"LB: $name (GCP $REGION)\":"
			echo "    - \"$ip\""
		fi
	done

	# Get global load balancers (only once, not per region)
	if [ "$REGION" = "${REGIONS[0]}" ]; then
		gcloud compute forwarding-rules list \
			--project="$PROJECT" \
			--global \
			--format="json" | jq -r '.[] | "\(.name)|\(.IPAddress // empty)"' | while IFS='|' read -r name ip; do

			if [ -n "$ip" ] && [ "$ip" != "null" ]; then
				# Format for YAML with global prefix
				echo "  \"LB: $name (GCP global)\":"
				echo "    - \"$ip\""
			fi
		done

		# Get external IP addresses
		gcloud compute addresses list \
			--project="$PROJECT" \
			--global \
			--format="json" | jq -r '.[] | "\(.name)|\(.address // empty)"' | while IFS='|' read -r name ip; do

			if [ -n "$ip" ] && [ "$ip" != "null" ]; then
				echo "  \"IP: $name (GCP global)\":"
				echo "    - \"$ip\""
			fi
		done

		# Get regional external IP addresses for each region
		for addr_region in "${REGIONS[@]}"; do
			gcloud compute addresses list \
				--project="$PROJECT" \
				--regions="$addr_region" \
				--format="json" | jq -r '.[] | "\(.name)|\(.address // empty)"' | while IFS='|' read -r name ip; do

				if [ -n "$ip" ] && [ "$ip" != "null" ]; then
					echo "  \"IP: $name (GCP $addr_region)\":"
					echo "    - \"$ip\""
				fi
			done
		done

		# Get Cloud SQL instances and their IP addresses
		gcloud sql instances list \
			--project="$PROJECT" \
			--format="json" | jq -r '.[] | 
            "\(.name)|\(.ipAddresses[]? | select(.type=="PRIMARY") | .ipAddress // empty)|\(.region)|\(.ipAddresses[]? | select(.type=="PRIVATE") | .ipAddress // empty)"' | while IFS='|' read -r name public_ip region private_ip; do

			if [ -n "$public_ip" ] && [ "$public_ip" != "null" ] && [ "$public_ip" != "" ]; then
				echo "  \"CloudSQL: $name (GCP $region)\":"
				echo "    - \"$public_ip\""
			fi

			if [ -n "$private_ip" ] && [ "$private_ip" != "null" ] && [ "$private_ip" != "" ]; then
				echo "  \"CloudSQL: $name private (GCP $region)\":"
				echo "    - \"$private_ip\""
			fi
		done
	fi
done
