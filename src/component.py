"""
Acumatica Extractor Component.

Extracts data from Acumatica ERP system via REST API and saves to Keboola tables.
"""

import csv
import json
import logging
import sys
from collections.abc import Iterator
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

        self.config = Configuration(**self.configuration.parameters)
        self.client: AcumaticaClient = self._init_client()

        logging.info("Config ID: %s", self._config_id)

    def _get_config_state_from_api(self) -> dict:
        """Get configuration-level state from Storage API (shared across all rows)."""
        if not self._storage_api_token or not self._config_id:
            logging.debug("No Storage API token or config ID, using local state file")
            return self.get_state_file()

        try:
            # TODO: remove hardcoded component id
            url = (
                self._storage_api_url
                + "/v2/storage/branch/default/components/keboola.ex-acumatica/configs/"
                + self._config_id
            )
            headers = {"X-StorageApi-Token": self._storage_api_token}
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 404:
                logging.debug("Configuration not found, returning empty state")
                return {}

            response.raise_for_status()
            logging.info("Storage API response: %s", response.text)
            try:
                config_data = response.json()
                logging.info(type(config_data))
                logging.info(type(config_data.get("state")))
                logging.info(list(config_data["state"].keys()))
                logging.info(type(config_data["state"]["#oauth_token_dict"]))
                logging.info(config_data["state"]["#oauth_token_dict"])
            except Exception as e:
                logging.error(f"Failed to parse JSON from Storage API response: {e}")
                return {}
            return config_data.get("state", {})
        except Exception as e:
            logging.warning(f"Failed to get configuration state from API: {e}. Using local state file.")
            return self.get_state_file()

    def _set_config_state_to_api(self, state: dict) -> None:
        """Set configuration-level state to Storage API (shared across all rows)."""
        if not self._storage_api_token or not self._config_id:
            logging.debug("No Storage API token or config ID, using local state file")
            self.write_state_file(state)
            return

        try:
            # TODO: remove hardcoded component id
            url = (
                self._storage_api_url
                + "/v2/storage/branch/default/components/keboola.ex-acumatica/configs/"
                + self._config_id
                + "/state"
            )

            headers = {"X-StorageApi-Token": self._storage_api_token, "Content-Type": "application/json"}
            payload = {"state": state}
            response = requests.put(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            logging.debug("Configuration state saved to Storage API")
        except Exception as e:
            logging.warning(f"Failed to save configuration state to API: {e}. Using local state file.")
            self.write_state_file(state)

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
        # Get configuration-level state (shared across all rows)
        state = self._get_config_state_from_api()
        state_oauth_token = state.get(KEY_STATE_OAUTH_TOKEN_DICT)

        # Debug OAuth Broker credentials
        oauth_creds = self.configuration.oauth_credentials
        if oauth_creds:
            creds_debug = {}
            for attr in dir(oauth_creds):
                if attr.startswith("_"):
                    continue

                try:
                    val = getattr(oauth_creds, attr)
                    if callable(val):
                        continue

                    if isinstance(val, dict):
                        dict_debug = {}
                        for k, v in val.items():
                            v_str = str(v)
                            if k == "created":
                                dict_debug[k] = v_str
                            else:
                                dict_debug[k] = v_str[:8] + "..." if len(v_str) > 8 else v_str
                        creds_debug[attr] = dict_debug
                    else:
                        val_str = str(val)
                        creds_debug[attr] = val_str[:8] + "..." if len(val_str) > 8 else val_str
                except Exception:
                    pass
            logging.info(f"OAuth Broker credentials fields: {creds_debug}")

        if self._state_contains_oauth_token(state_oauth_token):
            logging.debug("Initializing client from state")
            return self._init_client_from_state(state_oauth_token)
        else:
            logging.debug("Initializing client from OAuth credentials or username/password")
            return self._init_client_from_configuration()

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
                logging.info("OAuth credentials detected, using OAuth authentication")

                api_config = self.config.get_oauth_api_config(oauth_creds)

                logging.info(
                    f"client_id from get_oauth_api_config: {
                        api_config.oauth_client_id[:8] if api_config.oauth_client_id else 'None'
                    }..., "
                    f"client_secret from get_oauth_api_config: {
                        api_config.oauth_client_secret[:8] if api_config.oauth_client_secret else 'None'
                    }..."
                )

                client_id = getattr(oauth_creds, "appKey", None)
                client_secret = getattr(oauth_creds, "appSecret", None)

                logging.info(
                    f"appKey from oauth_creds: {client_id[:8] if client_id else 'None'}..., "
                    f"appSecret from oauth_creds: {client_secret[:8] if client_secret else 'None'}..."
                )

                if client_id:
                    api_config.oauth_client_id = client_id
                if client_secret:
                    api_config.oauth_client_secret = client_secret

                logging.info(
                    f"Final client_id: {api_config.oauth_client_id[:8] if api_config.oauth_client_id else 'None'}..., "
                    f"Final client_secret: {
                        api_config.oauth_client_secret[:8] if api_config.oauth_client_secret else 'None'
                    }..."
                )

                logging.info(
                    f"Loading OAuth tokens from config: access_token={api_config.oauth_access_token[:8]}..., "
                    f"refresh_token={api_config.oauth_refresh_token[:8]}..."
                )

                return AcumaticaClient(api_config, on_token_refresh=self.save_oauth_token_to_state)
        except (AttributeError, KeyError):
            logging.debug("No OAuth credentials found")

        logging.info("Using username/password authentication")
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
                logging.warning(f"Failed to encrypt OAuth token dict: {e}. Storing unencrypted.")
                encrypted_value = token_dict_json
        else:
            encrypted_value = token_dict_json

        if self._state is None:
            self._state = {}
        self._state[KEY_STATE_OAUTH_TOKEN_DICT] = encrypted_value

        logging.info(f"WRITING {len(self._state)} keys to {storage_location}")
        self._set_config_state_to_api(self._state)
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
            # Load configuration-level state (shared across all rows)
            self._state = self._get_config_state_from_api()
            logging.info(f"Loaded configuration state: {list(self._state.keys())}")

            logging.info("Starting Acumatica data extraction")

            self.client.authenticate()

            # Save OAuth token to state if using OAuth (don't refresh, just save)
            if self.client.config.oauth_access_token and self.client.config.oauth_refresh_token:
                self.save_oauth_token_to_state()

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
        """Update state file with new information."""
        from datetime import datetime

        if self._state is None:
            self._state = {}
        self._state["last_run_timestamp"] = datetime.now().isoformat()

        if KEY_STATE_OAUTH_TOKEN_DICT in self._state:
            oauth_data = json.loads(self._state[KEY_STATE_OAUTH_TOKEN_DICT])
            logging.info(f"_update_state writing refresh_token (first 20 chars): {oauth_data['refresh_token'][:20]}...")

        logging.info(f"WRITING configuration state with {len(self._state)} keys in _update_state")
        self._set_config_state_to_api(self._state)
        logging.debug("Configuration state updated")

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
