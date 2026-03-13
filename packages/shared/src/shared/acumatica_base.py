"""
Shared Acumatica component base — sync actions and token management mixin.

Provides everything that is identical between the extractor and writer:
- OAuth token management (init from state/config, save, refresh)
- Sync action implementations (listTenantVersions, listEndpoints, getOutputColumns)
"""

import json
import logging

import requests
from keboola.component.base import sync_action
from keboola.component.exceptions import UserException

from shared.acumatica_client import AcumaticaClient
from shared.swagger_parser import SwaggerParser

KEY_STATE_OAUTH_TOKEN_DICT = "#oauth_token_dict"


class AcumaticaSyncActionsMixin:
    """
    Mixin providing shared sync action implementations and token management for Acumatica components.

    Expects the inheriting class to have:
      - self.config  — AcumaticaConnectionConfig (or subclass)
      - self.client  — AcumaticaClient
      - self._state  — dict | None
      - self._component_id, self._project_id, self._storage_api_token,
        self._storage_api_url, self._config_id  — environment variables
    """

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
    def _load_state_oauth(state_oauth_token) -> dict:
        """Load OAuth data from state, handling both string and dict formats."""
        if isinstance(state_oauth_token, str):
            return json.loads(state_oauth_token)
        elif isinstance(state_oauth_token, dict):
            return state_oauth_token
        else:
            return {}

    def _init_client_from_state(self, state_oauth_token) -> AcumaticaClient:
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
        if not self.config.endpoints:
            raise UserException("Endpoint must be configured first")

        first_endpoint = self.config.endpoints[0]
        tenant_version = first_endpoint.tenant_version
        endpoint = first_endpoint.endpoint

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
