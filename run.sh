#!/bin/bash

json_file="../../Documents/test.json"
jq_command="../jq-macos-arm64"

# Read sources and sourcesContent arrays from the JSON file
sources=($(cat $json_file | $jq_command -r '.sources[]'))
sourcesContent=($(cat $json_file | $jq_command -r '.sourcesContent[]'))

# Iterate over the indices of the array
for ((i=0; i<${#sources[@]}; i++)); do
    source_file=${sources[$i]}
    content=${sourcesContent[$i]}

    # Check if the directory exists, create if not
    if [[ ! -d $(dirname "$source_file") ]]; then
        mkdir -p "$(dirname "$source_file")"
    fi

    # Create or update the file
    touch "$source_file"
    echo "$content" > "$source_file"
done
