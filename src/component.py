"""
Acumatica Extractor Component.

Extracts data from Acumatica ERP system via REST API and saves to Keboola tables.
"""

import csv
import json
import logging
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

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

    def __init__(self):
        super().__init__()
        self.config = Configuration(**self.configuration.parameters)
        self._state = None  # Cache state in memory
        self._init_client()

    def _init_client(self) -> None:
        """Initialize Acumatica client from state or OAuth credentials."""
        logging.debug("Initializing Acumatica client")
        state = self.get_state_file()
        state_oauth_token = state.get(KEY_STATE_OAUTH_TOKEN_DICT)

        if self._state_contains_oauth_token(state_oauth_token):
            logging.debug("Initializing client from state")
            self._init_client_from_state(state_oauth_token)
        else:
            logging.debug("Initializing client from OAuth credentials or username/password")
            self._init_client_from_config()

    def _state_contains_oauth_token(self, state_oauth_token: Any) -> bool:
        """Check if state contains valid OAuth token."""
        if not state_oauth_token:
            return False
        oauth_data = self._load_state_oauth(state_oauth_token)
        return bool(oauth_data.get("access_token"))

    @staticmethod
    def _load_state_oauth(state_oauth_token: Any) -> dict:
        """Load OAuth data from state, handling both string and dict formats."""
        if isinstance(state_oauth_token, str):
            return json.loads(state_oauth_token)
        elif isinstance(state_oauth_token, dict):
            return state_oauth_token
        else:
            return {}

    def _init_client_from_state(self, state_oauth_token: Any) -> None:
        """Initialize client using OAuth credentials from state."""
        oauth_data = self._load_state_oauth(state_oauth_token)

        # Try to get client credentials from OAuth credentials object
        try:
            oauth_creds = self.configuration.oauth_credentials
            client_id = getattr(oauth_creds, "#appKey", None) or getattr(oauth_creds, "appKey", None)
            client_secret = getattr(oauth_creds, "#appSecret", None) or getattr(oauth_creds, "appSecret", None)
        except Exception:
            client_id = oauth_data.get("client_id")
            client_secret = oauth_data.get("client_secret")
            logging.debug("Using client credentials from state")

        api_config = self.config.get_api_config()
        api_config.oauth_access_token = oauth_data.get("access_token", "")
        api_config.oauth_refresh_token = oauth_data.get("refresh_token", "")
        api_config.oauth_client_id = client_id or ""
        api_config.oauth_client_secret = client_secret or ""

        self.client = AcumaticaClient(api_config, on_token_refresh=self.save_oauth_token_to_state)

    def _init_client_from_config(self) -> None:
        """Initialize client using OAuth credentials from configuration or username/password."""
        # Check if OAuth credentials are available
        oauth_creds = None
        try:
            oauth_creds = self.configuration.oauth_credentials
            if oauth_creds and oauth_creds.data:
                logging.info("OAuth credentials detected, using OAuth authentication")

                # Get client credentials with # prefix for encrypted fields
                client_id = getattr(oauth_creds, "#appKey", None) or getattr(oauth_creds, "appKey", None)
                client_secret = getattr(oauth_creds, "#appSecret", None) or getattr(oauth_creds, "appSecret", None)

                api_config = self.config.get_oauth_api_config(oauth_creds)
                # Override with proper client credentials
                api_config.oauth_client_id = client_id or api_config.oauth_client_id
                api_config.oauth_client_secret = client_secret or api_config.oauth_client_secret

                self.client = AcumaticaClient(api_config, on_token_refresh=self.save_oauth_token_to_state)
                return
        except (AttributeError, KeyError):
            logging.debug("No OAuth credentials found")

        # Fallback to username/password
        logging.info("Using username/password authentication")
        self.client = AcumaticaClient(self.config.get_api_config(), on_token_refresh=self.save_oauth_token_to_state)

    def save_oauth_token_to_state(self) -> None:
        """Save the current OAuth token to state (without refreshing)."""
        logging.debug("Saving OAuth token to state")

        # Log the refresh token we're about to save
        logging.info(f"Saving refresh_token (first 20 chars): {self.client.config.oauth_refresh_token[:20]}...")

        # Save current tokens to state
        oauth_token_dict = {
            "access_token": str(self.client.config.oauth_access_token),
            "refresh_token": str(self.client.config.oauth_refresh_token),
            "client_id": str(self.client.config.oauth_client_id),
            "client_secret": str(self.client.config.oauth_client_secret),
            "token_type": "Bearer",
        }

        # Update in-memory state
        if self._state is None:
            self._state = {}
        self._state[KEY_STATE_OAUTH_TOKEN_DICT] = json.dumps(oauth_token_dict)

        # Write to disk
        logging.info(f"WRITING state file with {len(self._state)} keys")
        self.write_state_file(self._state)
        logging.info("OAuth token saved to state")

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
            self._state = self._load_previous_state()

            logging.info("Starting Acumatica data extraction")

            self.client.authenticate()

            # Save OAuth token to state if using OAuth (don't refresh, just save)
            if self.client.config.oauth_access_token and self.client.config.oauth_refresh_token:
                self.save_oauth_token_to_state()

            try:
                self._extract_endpoint(self.config.get_endpoint_config(), self.config.get_effective_page_size())
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

    def _load_previous_state(self) -> dict[str, Any]:
        """
        Load state from previous run.

        Returns:
            State dictionary from previous run.
        """
        state = self.get_state_file()
        logging.info(f"Loaded previous state: {state}")
        return state

    def _extract_endpoint(
        self,
        endpoint_config: EndpointConfig,
        page_size: int,
    ) -> None:
        """
        Extract data from a single Acumatica endpoint.

        Args:
            endpoint_config: Configuration for the endpoint to extract.
            page_size: Number of records to fetch per API request.
        """
        logging.info(f"Extracting endpoint: {endpoint_config.endpoint}")

        entities = self.client.get_entities(
            tenant_version=endpoint_config.tenant_version,
            endpoint=endpoint_config.endpoint,
            expand=endpoint_config.expand,
            filter_expr=endpoint_config.filter_expr,
            select=endpoint_config.select,
            top=page_size,
        )

        incremental = endpoint_config.load_type == "incremental_load"
        records_written = self._write_entities_to_table(entities, endpoint_config.output_table_name, incremental)

        logging.info(f"Extracted {records_written} records from {endpoint_config.endpoint}")

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
        output_table_path = self._get_output_table_path(table_name)

        # Collect all records and determine all columns
        flattened_records = []
        all_columns: set[str] = set()

        for entity in entities:
            flattened = self._flatten_entity(entity)
            flattened_records.append(flattened)
            all_columns.update(flattened.keys())

        records_written = len(flattened_records)
        csv_columns = sorted(all_columns)  # Sort for consistent column order

        if records_written > 0:
            with open(output_table_path, mode="w", encoding="utf-8", newline="") as out_file:
                writer = csv.DictWriter(out_file, fieldnames=csv_columns)
                writer.writeheader()

                for record in flattened_records:
                    writer.writerow(record)

            self._create_table_manifest(table_name, csv_columns, incremental)

        return records_written

    def _get_output_table_path(self, table_name: str) -> Path:
        """
        Get the full path for output table file.

        Args:
            table_name: Name of the output table.

        Returns:
            Path to the output CSV file.
        """
        tables_out_path = Path(self.tables_out_path)
        return tables_out_path / f"{table_name}.csv"

    def _create_table_manifest(self, table_name: str, columns: list[str], incremental: bool) -> None:
        """
        Create table manifest for output table.

        Args:
            table_name: Name of the output table.
            columns: List of column names.
            incremental: Whether to use incremental mode.
        """
        table = self.create_out_table_definition(name=f"{table_name}.csv", incremental=incremental, primary_key=[])
        self.write_manifest(table)
        logging.debug(f"Created manifest for table: {table_name}")

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
        """
        Update state file with new information.
        """
        from datetime import datetime

        # Update in-memory state with timestamp
        if self._state is None:
            self._state = {}
        self._state["last_run_timestamp"] = datetime.now().isoformat()

        # Debug: log what we're writing
        if KEY_STATE_OAUTH_TOKEN_DICT in self._state:
            oauth_data = json.loads(self._state[KEY_STATE_OAUTH_TOKEN_DICT])
            logging.info(f"_update_state writing refresh_token (first 20 chars): {oauth_data['refresh_token'][:20]}...")

        # Write to disk
        logging.info(f"WRITING state file with {len(self._state)} keys in _update_state")
        self.write_state_file(self._state)
        logging.debug("State file updated")

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
