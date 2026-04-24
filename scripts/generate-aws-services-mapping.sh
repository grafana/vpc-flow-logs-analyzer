#!/bin/bash

# Script to generate AWS services IP mapping from ip-ranges.amazonaws.com
# Usage: ./generate-aws-services-mapping.sh

set -e

# Download AWS IP ranges JSON silently
if ! IP_RANGES_JSON=$(curl -s https://ip-ranges.amazonaws.com/ip-ranges.json) || [ -z "$IP_RANGES_JSON" ]; then
    echo "Error: Failed to download AWS IP ranges" >&2
    exit 1
fi

echo "resource_names:"

# Use jq to deduplicate, prioritizing non-AMAZON services over AMAZON
echo "$IP_RANGES_JSON" | jq -r '
.prefixes[] | 
select(.ip_prefix != null and .service != null and .region != null) |
{
  service_region: ("AWS " + .service + " (" + .region + ")"),
  ip_prefix: .ip_prefix,
  service: .service
}
' | jq -s '
# Group by IP prefix to find duplicates
group_by(.ip_prefix) |
.[] |
# For each IP prefix, prefer non-AMAZON services over AMAZON
(sort_by(.service == "AMAZON") | .[0])
' | jq -rs 'group_by(.service_region) | 
.[] | 
"  \"" + .[0].service_region + "\":", 
(.[].ip_prefix | "    - \"" + . + "\"")
'