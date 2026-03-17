"""
Shared Acumatica component base — sync actions and token management.

Provides everything that is identical between the extractor and writer:
- OAuth token management (init from state/config, save, refresh)
- Sync action implementations (listTenantVersions, listEndpoints, loadFieldMapping, getOutputColumns)
"""

import json
import logging
import re
from typing import Any

import requests
from keboola.component.base import ComponentBase, sync_action
from keboola.component.exceptions import UserException

from shared.acumatica_client import AcumaticaClient
from shared.connection import AcumaticaConnectionConfig
from shared.swagger_parser import SwaggerParser

KEY_STATE_OAUTH_TOKEN_DICT = "#oauth_token_dict"


class AcumaticaSyncActionsMixin(ComponentBase):
    """
    Shared Acumatica component base providing OAuth token management and sync actions.

    Both extractor and writer inherit from this class. Subclasses must initialise
    the following instance attributes in their __init__:
      - config              — AcumaticaConnectionConfig (or subclass)
      - client              — AcumaticaClient
      - _state              — dict[str, Any] | None
      - _component_id       — str
      - _project_id         — str
      - _storage_api_token  — str
      - _storage_api_url    — str
      - _encryption_api_url — str
      - _config_id          — str
    """

    # Declared here so ty knows about them; subclasses assign in __init__
    config: AcumaticaConnectionConfig
    client: AcumaticaClient
    _state: dict[str, Any] | None
    _component_id: str
    _project_id: str
    _storage_api_token: str
    _storage_api_url: str
    _encryption_api_url: str
    _config_id: str

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
    def _load_state_oauth(state_oauth_token: Any) -> dict[str, Any]:
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
                oauth_data: dict[str, Any] = oauth_creds.data if oauth_creds else {}

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

        self._save_config_state(self._state)

    def _save_config_state(self, state: dict[str, Any]) -> None:
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
            payload = {"state": {"component": state}}
            response = requests.put(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            logging.info("Configuration state saved to Storage API")
        except Exception as e:
            logging.error(f"Failed to save configuration state to Storage API: {e}")

    def refresh_token_and_save_state(self) -> None:
        """Refresh the OAuth token and save it to state."""
        logging.info("Refreshing OAuth token and saving to state")
        self.client._refresh_oauth_token()
        self.save_oauth_token_to_state()
        logging.info("Token refreshed and saved to state")

    def _get_sync_action_endpoint(self) -> Any:
        """
        Return the endpoint config object used by sync actions.

        Default implementation returns the first item in config.endpoints (extractor).
        Writer overrides this to return self.config directly (flat single-endpoint config).
        """
        if not self.config.endpoints:
            raise UserException("Tenant/Version must be selected first to list endpoints")
        return self.config.endpoints[0]

    @sync_action("listTenantVersions")
    def list_tenant_versions(self) -> list[dict[str, str]]:
        """
        Fetch available tenant/version combinations from Acumatica /entity endpoint.

        Returns list of tenant/version strings for dropdown selection in UI.
        """
        return self.client.get_tenant_versions()

    @sync_action("listEndpoints")
    def list_endpoints(self) -> list[dict[str, str]]:
        """
        Fetch available endpoints from Acumatica swagger.json for selected tenant/version.

        Returns list of endpoints for dropdown selection in UI.
        """
        ep = self._get_sync_action_endpoint()
        tenant_version = ep.tenant_version
        if not tenant_version:
            raise UserException("Tenant/Version must be selected first to list endpoints")

        return self.client.get_endpoints(tenant_version)

    @sync_action("loadFieldMapping")
    def load_field_mapping(self) -> dict[str, Any]:
        """
        Auto-generate field mapping by fuzzy-matching input table columns to Acumatica API fields.

        Uses the configured input table mapping to get columns (explicit column list from
        the mapping config, or falls back to Storage API). Preserves any existing manually
        customized destination_field values.

        Returns pre-populated field_mapping[] array plus _metadata_ with all API fields
        for the destination dropdown.
        """
        ep = self._get_sync_action_endpoint()
        tenant_version = ep.tenant_version
        endpoint = ep.endpoint
        table_name = getattr(ep, "table_name", "")

        if not tenant_version:
            raise UserException("Tenant/Version must be selected first")
        if not endpoint:
            raise UserException("Endpoint must be selected first")
        if not table_name:
            raise UserException("Input table must be configured first")

        # Find the matching input table mapping
        input_mappings = self.configuration.tables_input_mapping
        table_mapping = next((t for t in input_mappings if t.destination == table_name), None)
        if not table_mapping:
            raise UserException(
                f"Input table '{table_name}' not found in input mapping. "
                "Please add the table to the input mapping first."
            )

        # Get columns: from mapping config if explicit, otherwise from Storage API
        columns = (
            table_mapping.columns if table_mapping.columns else self._get_table_columns_from_sapi(table_mapping.source)
        )

        if not columns:
            raise UserException(
                f"Could not determine columns for input table '{table_name}'. "
                "Please ensure the table exists in Keboola Storage."
            )

        # Fetch API fields from Swagger
        swagger_data = self.client.get_swagger_data(tenant_version)
        parser = SwaggerParser(swagger_data)
        api_fields = parser.get_entity_fields(endpoint)

        if not api_fields:
            raise UserException(f"No fields found in the schema for endpoint '{endpoint}'.")

        api_field_names = [f.name for f in api_fields]

        # Preserve existing manually customized mappings
        existing = {fm.source_column: fm.destination_field for fm in getattr(ep, "field_mapping", [])}

        # Build mapping — preserve existing, fuzzy-match new columns
        field_mapping = []
        for col in columns:
            if col in existing:
                destination = existing[col]
            else:
                destination = self._fuzzy_match_columns([col], api_field_names)[0]["destination_field"]
            field_mapping.append({"source_column": col, "destination_field": destination})

        return {
            "type": "data",
            "data": {
                **self.configuration.parameters,
                "field_mapping": field_mapping,
                "_metadata_": {"api_fields": [{"field_name": f.name, "label": f.name} for f in api_fields]},
            },
        }

    def _get_table_columns_from_sapi(self, table_id: str) -> list[str]:
        """Fetch table columns from Keboola Storage API by table ID."""
        if not self._storage_api_token or not self._storage_api_url:
            logging.warning("Storage API not available, skipping columns check for %s", table_id)
            return []
        try:
            response = requests.get(
                self._storage_api_url + "/v2/storage/tables/" + table_id,
                headers={"X-StorageApi-Token": self._storage_api_token},
                timeout=30,
            )
            if response.status_code == 404:
                return []
            if not response.ok:
                logging.warning("Failed to fetch columns for %s: HTTP %s", table_id, response.status_code)
                return []
            return response.json().get("columns", [])
        except Exception as e:
            logging.warning("Could not fetch columns for %s: %s", table_id, e)
            return []

    @staticmethod
    def _fuzzy_match_columns(csv_columns: list[str], api_fields: list[str]) -> list[dict[str, str]]:
        """
        Fuzzy-match CSV column names to API field names.

        Priority:
          1. Exact match
          2. Case-insensitive match
          3. Normalized match (strip _, -, spaces; lowercase)

        Unmatched columns get an empty destination_field.
        """

        def normalize(s: str) -> str:
            return re.sub(r"[_\-\s.]", "", s).lower()

        api_lower = {f.lower(): f for f in api_fields}
        api_normalized = {normalize(f): f for f in api_fields}

        mapping: list[dict[str, str]] = []
        for col in csv_columns:
            dest = ""
            if col in api_fields:
                dest = col
            elif col.lower() in api_lower:
                dest = api_lower[col.lower()]
            elif normalize(col) in api_normalized:
                dest = api_normalized[normalize(col)]

            mapping.append({"source_column": col, "destination_field": dest})

        return mapping

    @sync_action("getOutputColumns")
    def get_output_columns(self) -> list[dict[str, str]]:
        """
        Fetch available columns/fields from the swagger schema for the selected endpoint.

        Returns list of field names that can be used as primary keys.
        """
        ep = self._get_sync_action_endpoint()
        tenant_version = ep.tenant_version
        endpoint = ep.endpoint

        if not tenant_version:
            raise UserException("Tenant/Version must be selected first")
        if not endpoint:
            raise UserException("Endpoint must be selected first")

        swagger_data = self.client.get_swagger_data(tenant_version)
        parser = SwaggerParser(swagger_data)
        columns = parser.get_entity_primary_key_candidates(endpoint)

        if not columns:
            raise UserException(f"No columns found in the schema for endpoint '{endpoint}'.")

        return [
            {
                "label": col.name + (" (required)" if col.required else ""),
                "value": col.name,
            }
            for col in columns
        ]
