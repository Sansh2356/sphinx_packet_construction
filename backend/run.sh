#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <output_directory> <input_file>"
    exit 1
fi

# Assign arguments to variables
output_directory="$1"
input_file="$2"

# Please fill in the version of the programming language you used here to help us with debugging if we run into problems!
version="rustc - 1.92.0 cargo 1.92.0 6.14.0-37-generic #37~24.04.1-Ubuntu"

# Check if the 'version' variable is not null
if [ -z "$version" ]; then
    echo "Please fill in the version of the programming language you used."
    exit 1
fi

# Your run command here:

cwd=$(pwd)
final_path=$cwd"/backend/Cargo.toml"
cargo run --manifest-path $final_path -- $output_directory $input_file 