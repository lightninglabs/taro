#!/bin/bash
# This script will check Go-version conformance in relevant docker files. Else, exit with error
# A Makefile linter-target runs this script

# Function to check if a Dockerfile contains only the stipulated Go version
check_go_version() {
    local dockerfile="$1"
    local required_go_version="$2"

    # Extract the Go version used in $dockerfile
    local extracted_go_version=$(grep -i '^FROM golang:' "$dockerfile" | tr -d "_-:' [:alpha:]")

    # Check if Dockerfile only contains stipulated Go version
    if [ "$extracted_go_version" != "$required_go_version" ]; then
        echo "FAIL: $dockerfile specifies Go version '$extracted_go_version' violating conformance. '$required_go_version' is required."
    else
        echo "$dockerfile specifies Go version $required_go_version."
    fi
}

# Export function to be accessible by subshells e.g. `find -exec`
export -f check_go_version

# Check if the target Go version argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_go_version>"
    exit 1
fi

target_go_version="$1"

# Run check_go_version on Dockerfiles files present in non pruned directory
find . \
    -path ./vendor -prune -o \
    -type f \
    \( -name "*.Dockerfile" -o -name "Dockerfile" \) \
    -exec bash -c 'check_go_version $1 '"$target_go_version" bash {} \;

echo "All Dockerfiles pass the Go version check for Go version $target_go_version."
