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
from configuration import Configuration, EndpointConfig
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
        self._component_id: str = env.component_id
        self._project_id: str = env.project_id
        self._storage_api_token: str = env.token
        self._storage_api_url: str = env.url or ""
        self._encryption_api_url: str = self._storage_api_url.replace("connection", "encryption")
        self._config_id: str = env.config_id
        self._state = self.get_state_file()

        self.config = Configuration(**self.configuration.parameters)
        self.client: AcumaticaClient = self._init_client()

    def _encrypt_value(self, value: str) -> str:
        """Encrypt a value using Keboola encryption API."""
        url = self._encryption_api_url + "/encrypt"
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

                # Check if state actually contains valid OAuth data
                if state_oauth_token:
                    oauth_data = self._load_state_oauth(state_oauth_token)
                    if oauth_data.get("access_token") and oauth_data.get("refresh_token"):
                        logging.info("Valid OAuth tokens found in state")
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

        return AcumaticaClient(
            acumatica_url=self.config.acumatica_url,
            on_token_refresh=self.save_oauth_token_to_state,
            oauth_access_token=oauth_data.get("access_token", ""),
            oauth_refresh_token=oauth_data.get("refresh_token", ""),
            oauth_client_id=oauth_data.get("client_id", ""),
            oauth_client_secret=oauth_data.get("client_secret", ""),
            oauth_expires_in=oauth_data.get("expires_in", 0),
            oauth_token_received_at=oauth_data.get("token_received_at", 0.0),
            oauth_scope=oauth_data.get("scope", ""),
        )

    def _init_client_from_configuration(self) -> AcumaticaClient:
        """Initialize client using OAuth credentials from configuration."""
        try:
            oauth_creds = self.configuration.oauth_credentials
            if oauth_creds:
                oauth_data = oauth_creds.data if oauth_creds else {}

                logging.info(
                    f"Loading OAuth tokens from config: access_token={oauth_data.get('access_token', '')[:8]}..., "
                    f"refresh_token={oauth_data.get('refresh_token', '')[:8]}..."
                )

                return AcumaticaClient(
                    acumatica_url=self.config.acumatica_url,
                    on_token_refresh=self.save_oauth_token_to_state,
                    oauth_access_token=oauth_data.get("access_token", ""),
                    oauth_refresh_token=oauth_data.get("refresh_token", ""),
                    oauth_client_id=getattr(oauth_creds, "appKey", ""),
                    oauth_client_secret=getattr(oauth_creds, "appSecret", ""),
                    oauth_expires_in=oauth_data.get("expires_in", 0),
                    oauth_token_received_at=oauth_data.get("token_received_at", 0.0),
                    oauth_scope=oauth_data.get("scope", ""),
                )
        except (AttributeError, KeyError):
            pass

        logging.warning("Using username/password authentication")
        return AcumaticaClient(
            acumatica_url=self.config.acumatica_url,
            on_token_refresh=self.save_oauth_token_to_state,
            acumatica_username=self.config.acumatica_username,
            acumatica_password=self.config.acumatica_password,
        )

    def save_oauth_token_to_state(self) -> None:
        """Save the current OAuth token to local state file."""
        logging.info(
            f"Saving OAuth tokens: access_token={self.client.oauth_access_token[:8]}..., "
            f"refresh_token={self.client.oauth_refresh_token[:8]}..."
        )

        oauth_token_dict = {
            "access_token": str(self.client.oauth_access_token),
            "refresh_token": str(self.client.oauth_refresh_token),
            "expires_in": int(self.client.oauth_expires_in),
            "token_received_at": float(self.client.oauth_token_received_at),
            "scope": str(self.client.oauth_scope),
            "client_id": str(self.client.oauth_client_id),
            "client_secret": str(self.client.oauth_client_secret),
            "token_type": "Bearer",
        }

        token_dict_json = json.dumps(oauth_token_dict)

        # Only encrypt in Keboola production environment
        if self._component_id and self._project_id:
            try:
                encrypted_value = self._encrypt_value(token_dict_json)
                logging.debug("OAuth token dict encrypted successfully")
            except Exception as e:
                logging.warning(f"Failed to encrypt OAuth token dict: {e}. Storing unencrypted.")
                encrypted_value = token_dict_json
        else:
            logging.debug("Running locally, storing OAuth tokens unencrypted")
            encrypted_value = token_dict_json

        if self._state is None:
            self._state = {}
        self._state[KEY_STATE_OAUTH_TOKEN_DICT] = encrypted_value

        self.write_state_file(self._state)
        logging.info("OAuth tokens successfully saved to local state file")

        # Also save to Storage API for persistence in case component fails later
        self._save_config_state(self._state)

    def _save_config_state(self, state: dict) -> None:
        """Set configuration-level state to Storage API (shared across all rows)."""
        if not self._storage_api_token or not self._config_id:
            logging.debug("No Storage API token or config ID, skipping Storage API state save")
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
            # Wrap state in "component" key as required by Storage API
            payload = {"state": {"component": state}}
            response = requests.put(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            logging.info("Configuration state saved to Storage API")
        except Exception as e:
            logging.error(f"Failed to save configuration state to Storage API: {e}")

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

            if not self.config.endpoints:
                raise UserException("No endpoints configured. Please add at least one endpoint to extract.")

            self.client.authenticate()

            try:
                # Extract each configured endpoint
                enabled_endpoints = [ep for ep in self.config.endpoints if ep.enabled]
                if not enabled_endpoints:
                    logging.warning("No enabled endpoints configured. Skipping extraction.")
                    return

                for idx, endpoint_config in enumerate(enabled_endpoints, 1):
                    logging.info(f"Processing endpoint {idx}/{len(enabled_endpoints)}: {endpoint_config.endpoint}")
                    self._extract_endpoint(endpoint_config)

                self._update_state()
                logging.info(
                    f"Acumatica data extraction completed successfully ({len(self.config.endpoints)} endpoints)"
                )
            finally:
                # Logout only for username/password auth to free up API user slot
                # OAuth doesn't need logout
                if self.client.acumatica_username and not self.client.oauth_access_token:
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

    def _extract_endpoint(self, endpoint_config: "EndpointConfig") -> None:
        """Extract data from a single Acumatica endpoint."""
        logging.info(f"Extracting endpoint: {endpoint_config.endpoint}")

        entities = self.client.get_entities(
            tenant_version=endpoint_config.tenant_version,
            endpoint=endpoint_config.endpoint,
            expand=endpoint_config.expand,
            filter_expr=endpoint_config.filter_expr,
            select=endpoint_config.select,
            top=self.config.page_size,
        )

        output_table_name = f"{endpoint_config.endpoint}.csv"
        incremental = self.config.destination.load_type == "incremental_load"
        primary_keys = endpoint_config.primary_keys
        records_written = self._write_entities_to_table(entities, output_table_name, incremental, primary_keys)

        logging.info(f"Extracted {records_written} records from {endpoint_config.endpoint}")

    def _write_entities_to_table(
        self, entities: Iterator[dict[str, Any]], table_name: str, incremental: bool, primary_keys: list[str]
    ) -> int:
        """
        Write entities to output table as CSV.

        Flattens nested structures and handles various data types.

        Args:
            entities: Iterator of entity dictionaries from API.
            table_name: Name of the output table.
            incremental: Whether to use incremental mode.
            primary_keys: List of primary key columns.

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
            table = self.create_out_table_definition(name=table_name, incremental=incremental, primary_key=primary_keys)
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
        if self._state is None:
            self._state = {}

        self._state["last_run_timestamp"] = datetime.now().isoformat()

        logging.info("Writing last_run_timestamp to local state file")
        self.write_state_file(self._state)
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
        # Get tenant_version from first endpoint config
        if not self.config.endpoints:
            raise UserException("Tenant/Version must be selected first to list endpoints")

        tenant_version = self.config.endpoints[0].tenant_version
        if not tenant_version:
            raise UserException("Tenant/Version must be selected first to list endpoints")

        return self.client.get_endpoints(tenant_version)

    @sync_action("getOutputColumns")
    def get_output_columns(self):
        """
        Fetch available columns/fields from the swagger schema for the selected endpoint.

        Returns list of field names that can be used as primary keys.
        """
        # Get values from first endpoint config
        if not self.config.endpoints:
            raise UserException("Endpoint must be configured first")

        first_endpoint = self.config.endpoints[0]
        tenant_version = first_endpoint.tenant_version
        endpoint = first_endpoint.endpoint

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
