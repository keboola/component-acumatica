#!/usr/bin/env bash

set -e

# Check if the KBC_DEVELOPERPORTAL_APP environment variable is set
if [ -z "$KBC_DEVELOPERPORTAL_APP" ]; then
    echo "Error: KBC_DEVELOPERPORTAL_APP environment variable is not set."
    exit 1
fi

# Require extractor|writer argument to locate component_config/
component="${1:-}"
if [ -z "$component" ]; then
    echo "Error: component argument required (extractor or writer)."
    exit 1
fi

config_dir="${component}/component_config"

# Pull the latest version of the developer portal CLI Docker image
docker pull quay.io/keboola/developer-portal-cli-v2:latest

# Function to update a property for the given app ID
update_property() {
    local app_id="$1"
    local prop_name="$2"
    local file_path="$3"

    if [ ! -f "$file_path" ]; then
        echo "File '$file_path' not found. Skipping update for property '$prop_name' of application '$app_id'."
        return
    fi

    # shellcheck disable=SC2155
    local value=$(<"$file_path")

    echo "Updating $prop_name for $app_id"
    echo "$value"

    if [ -n "$value" ]; then
        docker run --rm \
            -e KBC_DEVELOPERPORTAL_USERNAME \
            -e KBC_DEVELOPERPORTAL_PASSWORD \
            quay.io/keboola/developer-portal-cli-v2:latest \
            update-app-property "$KBC_DEVELOPERPORTAL_VENDOR" "$app_id" "$prop_name" --value="$value"
        echo "Property $prop_name updated successfully for $app_id"
    else
        echo "$prop_name is empty for $app_id, skipping..."
    fi
}

app_id="$KBC_DEVELOPERPORTAL_APP"

update_property "$app_id" "isDeployReady" "${config_dir}/isDeployReady.md"
update_property "$app_id" "longDescription" "${config_dir}/component_long_description.md"
update_property "$app_id" "configurationSchema" "${config_dir}/configSchema.json"
update_property "$app_id" "configurationRowSchema" "${config_dir}/configRowSchema.json"
update_property "$app_id" "configurationDescription" "${config_dir}/configuration_description.md"
update_property "$app_id" "shortDescription" "${config_dir}/component_short_description.md"
update_property "$app_id" "logger" "${config_dir}/logger"
update_property "$app_id" "loggerConfiguration" "${config_dir}/loggerConfiguration.json"
update_property "$app_id" "licenseUrl" "${config_dir}/licenseUrl.md"
update_property "$app_id" "documentationUrl" "${config_dir}/documentationUrl.md"
update_property "$app_id" "sourceCodeUrl" "${config_dir}/sourceCodeUrl.md"
update_property "$app_id" "uiOptions" "${config_dir}/uiOptions.md"

# Update the actions.md file
source "$(dirname "$0")/fn_actions_md_update.sh"
# update_property actions
update_property "$app_id" "actions" "${config_dir}/actions.md"
