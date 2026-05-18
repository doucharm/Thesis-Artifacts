#!/usr/bin/env bash
set -euo pipefail
FILE="${1:-}"
[[ -z "$FILE" || ! -f "$FILE" ]] && echo "Invalid compose file" && exit 1
mapfile -t IMAGES < <(yq -r '.services[].image' "$FILE" | grep -v '^null$') # Find all the services and extract the image field, ignoring null values
IMAGES=($(printf "%s\n" "${IMAGES[@]}" | sort -u)) # Remove duplicates and sort the list
[[ ${#IMAGES[@]} -eq 0 ]] && echo "##vso[task.setvariable variable=imageMatrix;isOutput=true]{}" && exit 0
JSON="{"
for IMG in "${IMAGES[@]}"; do
  NAME=$(echo "$IMG" | sed 's/[^a-zA-Z0-9]/_/g') # Create a valid JSON key by replacing non-alphanumeric characters with underscores
  JSON+="\"scan_${NAME}\":{\"IMAGE_TO_SCAN\":\"$IMG\"},"
done
JSON="${JSON%,}}"
echo "##vso[task.setvariable variable=imageMatrix;isOutput=true]$JSON" #    Set the output variable for Azure DevOps with the JSON matrix
