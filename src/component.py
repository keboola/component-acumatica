"""
Acumatica Extractor Component.

Extracts data from Acumatica ERP system via REST API and saves to Keboola tables.
"""

import csv
import json
import logging
import sys
from collections.abc import Iterator
from datetime import datetime
from typing import Any

import requests
from keboola.component.base import ComponentBase, sync_action
from keboola.component.exceptions import UserException

from acumatica_client import AcumaticaClient
from configuration import Configuration
from swagger_parser import SwaggerParser

KEY_STATE_OAUTH_TOKEN_DICT = "#oauth_token_dict"


class Component(ComponentBase):
    """
    Acumatica Extractor Component.

    Extracts data from configured Acumatica endpoint and writes result to output table.
    """

    def __init__(self) -> None:
        super().__init__()
        self._state: dict[str, Any] | None = None

        env = self.environment_variables
        self._storage_api_token: str = env.token
        self._storage_api_url: str = env.url or "https://connection.keboola.com"
        self._config_id: str = env.config_id
        self._component_id: str = env.component_id
        self._project_id: str = env.project_id
        self._state = self._load_config_state()

        self.config = Configuration(**self.configuration.parameters)
        self.client: AcumaticaClient = self._init_client()

    def _load_config_state(self) -> dict:
        """Get configuration-level state from Storage API (shared across all rows)."""
        if not self._storage_api_token or not self._config_id:
            logging.debug("No Storage API token or config ID, using local state file")
            return self.get_state_file()

        try:
            url = (
                self._storage_api_url
                + "/v2/storage/branch/default/components/"
                + self._component_id
                + "/configs/"
                + self._config_id
            )
            headers = {"X-StorageApi-Token": self._storage_api_token}
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 404:
                logging.debug("Configuration not found, returning empty state")
                return {}

            response.raise_for_status()
            config_data = response.json()
            return config_data.get("state", {})
        except Exception as e:
            logging.warning(f"Failed to get configuration state from Storage API: {e}")
            return {}

    def _save_config_state(self, state: dict) -> None:
        """Set configuration-level state to Storage API (shared across all rows)."""
        if not self._storage_api_token or not self._config_id:
            logging.debug("No Storage API token or config ID, using local state file")
            self.write_state_file(state)
            return

        try:
            url = (
                self._storage_api_url
                + "/v2/storage/branch/default/components/"
                + self._component_id
                + "/configs/"
                + self._config_id
                + "/state"
            )

            headers = {"X-StorageApi-Token": self._storage_api_token, "Content-Type": "application/json"}
            payload = {"state": state}
            response = requests.put(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            logging.debug("Configuration state saved to Storage API")
        except Exception as e:
            logging.error(f"Failed to save configuration state to API: {e}")

    def _encrypt_value(self, value: str) -> str:
        """Encrypt a value using Keboola encryption API."""
        url = "https://encryption.keboola.com/encrypt"
        params = {
            "componentId": self._component_id,
            "projectId": self._project_id,
        }
        headers = {"Content-Type": "text/plain"}
        response = requests.post(url, data=value, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text

    def _init_client(self) -> AcumaticaClient:
        """Initialize Acumatica client from state or OAuth credentials."""
        logging.debug("Initializing Acumatica client")

        if self._state:
            try:
                logging.debug("Initializing client from state")
                state_oauth_token = self._state.get(KEY_STATE_OAUTH_TOKEN_DICT)
                return self._init_client_from_state(state_oauth_token)
            except json.JSONDecodeError:
                logging.warning(
                    "Failed to initialize client from state: error decoding JSON state. Keys: %s",
                    ", ".join(sorted(self._state.keys())),
                )
            except Exception as e:
                logging.warning(f"Failed to initialize client from state: {e}")

        logging.debug("Initializing client from configuration")
        return self._init_client_from_configuration()

    @staticmethod
    def _load_state_oauth(state_oauth_token: Any) -> dict:
        """Load OAuth data from state, handling both string and dict formats."""
        if isinstance(state_oauth_token, str):
            return json.loads(state_oauth_token)
        elif isinstance(state_oauth_token, dict):
            return state_oauth_token
        else:
            return {}

    def _init_client_from_state(self, state_oauth_token: Any) -> AcumaticaClient:
        """Initialize client using OAuth credentials from state."""
        oauth_data = self._load_state_oauth(state_oauth_token)

        logging.info(
            f"Loading OAuth tokens from state: access_token={oauth_data.get('access_token', '')[:8]}..., "
            f"refresh_token={oauth_data.get('refresh_token', '')[:8]}..."
        )

        api_config = self.config.get_api_config()
        api_config.oauth_access_token = oauth_data.get("access_token", "")
        api_config.oauth_refresh_token = oauth_data.get("refresh_token", "")
        api_config.oauth_expires_in = oauth_data.get("expires_in", 0)
        api_config.oauth_token_received_at = oauth_data.get("token_received_at", 0.0)
        api_config.oauth_scope = oauth_data.get("scope", "")
        api_config.oauth_client_id = oauth_data.get("client_id", "")
        api_config.oauth_client_secret = oauth_data.get("client_secret", "")

        return AcumaticaClient(api_config, on_token_refresh=self.save_oauth_token_to_state)

    def _init_client_from_configuration(self) -> AcumaticaClient:
        """Initialize client using OAuth credentials from configuration."""
        try:
            oauth_creds = self.configuration.oauth_credentials
            if oauth_creds:
                logging.debug("OAuth credentials detected, using OAuth authentication")

                api_config = self.config.get_oauth_api_config(oauth_creds)

                client_id = getattr(oauth_creds, "appKey", None)
                client_secret = getattr(oauth_creds, "appSecret", None)

                if client_id:
                    api_config.oauth_client_id = client_id
                if client_secret:
                    api_config.oauth_client_secret = client_secret

                logging.debug(
                    f"Loading OAuth tokens from config: access_token={api_config.oauth_access_token[:8]}..., "
                    f"refresh_token={api_config.oauth_refresh_token[:8]}..."
                )

                return AcumaticaClient(api_config, on_token_refresh=self.save_oauth_token_to_state)
        except (AttributeError, KeyError):
            logging.debug("No OAuth credentials found")

        logging.warning("Using username/password authentication")
        return AcumaticaClient(self.config.get_api_config(), on_token_refresh=self.save_oauth_token_to_state)

    def save_oauth_token_to_state(self) -> None:
        """Save the current OAuth token to state."""
        storage_location = (
            "Storage API (global config)" if (self._storage_api_token and self._config_id) else "local state file"
        )
        logging.info(
            f"Saving OAuth tokens to {storage_location}: access_token={self.client.config.oauth_access_token[:8]}..., "
            f"refresh_token={self.client.config.oauth_refresh_token[:8]}..."
        )

        oauth_token_dict = {
            "access_token": str(self.client.config.oauth_access_token),
            "refresh_token": str(self.client.config.oauth_refresh_token),
            "expires_in": int(self.client.config.oauth_expires_in),
            "token_received_at": float(self.client.config.oauth_token_received_at),
            "scope": str(self.client.config.oauth_scope),
            "client_id": str(self.client.config.oauth_client_id),
            "client_secret": str(self.client.config.oauth_client_secret),
            "token_type": "Bearer",
        }

        token_dict_json = json.dumps(oauth_token_dict)
        if self._storage_api_token and self._config_id:
            try:
                encrypted_value = self._encrypt_value(token_dict_json)
                logging.debug("OAuth token dict encrypted successfully")
            except Exception as e:
                logging.warning(f"Failed to encrypt OAuth token dict: {e}")
                raise
        else:
            encrypted_value = token_dict_json

        if self._state is None:
            self._state = {}
        self._state[KEY_STATE_OAUTH_TOKEN_DICT] = encrypted_value

        logging.info(f"WRITING {len(self._state)} keys to {storage_location}")
        self._save_config_state(self._state)
        logging.info(f"OAuth tokens successfully saved to {storage_location}")

    def refresh_token_and_save_state(self) -> None:
        """Refresh the OAuth token and save it to state."""
        logging.info("Refreshing OAuth token and saving to state")

        # Refresh the token
        self.client._refresh_oauth_token()

        # Save updated tokens to state
        self.save_oauth_token_to_state()
        logging.info("Token refreshed and saved to state")

    def run(self) -> None:
        """Main execution - orchestrates the component workflow."""
        try:
            logging.info("Starting Acumatica data extraction")

            self.client.authenticate()

            try:
                self._extract_endpoint()
                self._update_state()
                logging.info("Acumatica data extraction completed successfully")
            finally:
                # Always logout to free up API user slot
                self.client.logout()

        except UserException:
            raise
        except Exception as e:
            error_msg = str(e)

            # Check for API login limit in the error message
            if "too many 500 error responses" in error_msg and "auth/login" in error_msg:
                raise UserException(
                    "API Login Limit reached. The Acumatica instance has too many active API sessions. "
                    "Please wait for existing sessions to expire or contact your Acumatica administrator "
                    "to increase the API user limit or manually log out active API users."
                )

            logging.exception("Unhandled error during extraction")
            raise UserException(f"Extraction failed: {error_msg}")

    def _extract_endpoint(self) -> None:
        """Extract data from the configured Acumatica endpoint."""
        logging.info(f"Extracting endpoint: {self.config.endpoint}")

        entities = self.client.get_entities(
            tenant_version=self.config.tenant_version,
            endpoint=self.config.endpoint,
            expand=self.config.expand,
            filter_expr=self.config.filter_expr,
            select=self.config.select,
            top=self.config.get_effective_page_size(),
        )

        output_table_name = f"{self.config.endpoint}.csv"
        incremental = self.config.destination.load_type == "incremental_load"
        records_written = self._write_entities_to_table(entities, output_table_name, incremental)

        logging.info(f"Extracted {records_written} records from {self.config.endpoint}")

    def _write_entities_to_table(self, entities: Iterator[dict[str, Any]], table_name: str, incremental: bool) -> int:
        """
        Write entities to output table as CSV.

        Flattens nested structures and handles various data types.

        Args:
            entities: Iterator of entity dictionaries from API.
            table_name: Name of the output table.
            incremental: Whether to use incremental mode.

        Returns:
            Number of records written.
        """
        # Collect all records and determine all columns
        flattened_records = []
        all_columns: set[str] = set()

        for entity in entities:
            flattened = self._flatten_entity(entity)
            flattened_records.append(flattened)
            all_columns.update(flattened.keys())

        records_written = len(flattened_records)
        csv_columns = sorted(all_columns)

        if records_written > 0:
            table = self.create_out_table_definition(name=table_name, incremental=incremental, primary_key=[])
            logging.info(f"Table full_path: {table.full_path}")
            logging.info(f"Writing {records_written} records to {table.full_path}")

            with open(table.full_path, mode="w", encoding="utf-8", newline="") as out_file:
                writer = csv.DictWriter(out_file, fieldnames=csv_columns)
                writer.writeheader()
                for record in flattened_records:
                    writer.writerow(record)

            logging.info("File written, now writing manifest")
            # Write manifest after all data is written
            self.write_manifest(table)
            logging.info(f"Manifest written for table: {table_name}")

        return records_written

    @staticmethod
    def _flatten_entity(entity: dict[str, Any], parent_key: str = "", sep: str = "_") -> dict[str, Any]:
        """
        Flatten nested dictionary structure.

        Converts nested dictionaries to flat structure with concatenated keys.
        Example: {'a': {'b': 1}} becomes {'a_b': 1}

        Args:
            entity: Entity dictionary to flatten.
            parent_key: Parent key for nested structures.
            sep: Separator for concatenating keys.

        Returns:
            Flattened dictionary.
        """
        items: list[tuple[str, Any]] = []

        for key, value in entity.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key

            if isinstance(value, dict) and value:
                # Recursively flatten nested dictionaries
                items.extend(Component._flatten_entity(value, new_key, sep).items())
            elif isinstance(value, list):
                # Convert lists to JSON-like string representation
                items.append((new_key, str(value)))
            else:
                # Keep primitive values as-is
                items.append((new_key, value))

        return dict(items)

    def _update_state(self) -> None:
        """Update local state file with last run timestamp."""
        local_state = {"last_run_timestamp": datetime.now().isoformat()}

        logging.info("Writing last_run_timestamp to local state file")
        self.write_state_file(local_state)
        logging.debug("Local state file updated")

    @sync_action("listTenantVersions")
    def list_tenant_versions(self):
        """
        Fetch available tenant/version combinations from Acumatica /entity endpoint.

        Returns list of tenant/version strings for dropdown selection in UI.
        """
        return self.client.get_tenant_versions()

    @sync_action("listEndpoints")
    def list_endpoints(self):
        """
        Fetch available endpoints from Acumatica swagger.json for selected tenant/version.

        Returns list of endpoints for dropdown selection in UI.
        """
        tenant_version = self.configuration.parameters.get("tenant_version")
        if not tenant_version:
            raise UserException("Tenant/Version must be selected first to list endpoints")

        return self.client.get_endpoints(tenant_version)

    @sync_action("getOutputColumns")
    def get_output_columns(self):
        """
        Fetch available columns/fields from the swagger schema for the selected endpoint.

        Returns list of field names that can be used as primary keys.
        """
        tenant_version = self.configuration.parameters.get("tenant_version")
        endpoint = self.configuration.parameters.get("endpoint")

        if not tenant_version:
            raise UserException("Tenant/Version must be selected first")
        if not endpoint:
            raise UserException("Endpoint must be selected first")

        # Fetch swagger data
        swagger_data = self.client.get_swagger_data(tenant_version)

        # Parse swagger to get entity fields
        parser = SwaggerParser(swagger_data)
        columns = parser.get_entity_primary_key_candidates(endpoint)

        if not columns:
            raise UserException(f"No columns found in the schema for endpoint '{endpoint}'.")

        # Return in the format expected by the UI
        result = []
        for col in columns:
            result.append(
                {
                    "label": col.name + (" (required)" if col.required else ""),
                    "value": col.name,
                }
            )
        return result


"""
Main entrypoint
"""
if __name__ == "__main__":
    try:
        comp = Component()
        comp.execute_action()
    except UserException as exc:
        logging.exception(exc)
        sys.exit(1)
    except Exception as exc:
        logging.exception(exc)
        sys.exit(2)
