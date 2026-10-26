#!/bin/bash

# Requires `component` and `config_dir` to be set by the caller (update_properties.sh)
MD_FILE="${config_dir}/actions.md"

# Sync actions are declared in the component's own src/ and in the shared base class under packages/
SYNC_ACTIONS=$(grep -roh -E "@sync_action\(['\"][^'\"]*['\"]\)" "${component}/src/" packages/ | sed "s/@sync_action(\(['\"]\)\([^'\"]*\)\(['\"]\))/\2/" | sort | uniq)

# Check if any sync actions were found
if [ -n "$SYNC_ACTIONS" ]; then
    # Iterate over each occurrence of @sync_action('XXX')
    for sync_action in $SYNC_ACTIONS; do
        EXISTING_ACTIONS+=("$sync_action")
    done

    # Convert the array to JSON format
    JSON_ACTIONS=$(printf '"%s",' "${EXISTING_ACTIONS[@]}")
    JSON_ACTIONS="[${JSON_ACTIONS%,}]"

    # Update the content of the actions.md file
    echo "$JSON_ACTIONS" > "$MD_FILE"
else
    echo "No sync actions found. Not creating the file."
fi
