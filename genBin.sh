#!/bin/bash

# Check if a hex string is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <HEX_STRING>"
    exit 1
fi

hex="$1"
filename="${hex}.bin"

# Check that hex contains only valid characters
if ! [[ "$hex" =~ ^[0-9A-Fa-f]+$ ]]; then
    echo "Invalid hex string"
    exit 1
fi

# Check that the hex string has even length (2 hex = 1 byte)
if (( ${#hex} % 2 != 0 )); then
    echo "Hex string must have even length"
    exit 1
fi

# Create the binary file
echo "$hex" | xxd -r -p > "data_files/$filename"

echo "Created file: $filename"