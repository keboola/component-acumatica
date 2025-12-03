"""
Acumatica API client for authentication and data retrieval.

Handles all interactions with the Acumatica REST API including:
- Authentication with username/password
- Session management with cookies
- Entity retrieval with OData parameters
- Error handling and retries
"""

import logging
from collections.abc import Iterator
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from configuration import AcumaticaApiConfig


class AcumaticaClient:
    """Client for interacting with Acumatica REST API."""

    def __init__(self, config: AcumaticaApiConfig, on_token_refresh=None):
        """
        Initialize Acumatica API client.

        Args:
            config: API configuration containing URL, credentials, and company.
            on_token_refresh: Optional callback to invoke after successful token refresh.
        """
        self.config = config
        self.base_url = config.acumatica_url
        self.session = self._create_session()
        self._authenticated = False
        self.on_token_refresh = on_token_refresh

    def _create_session(self) -> requests.Session:
        """
        Create requests session with retry strategy.

        Returns:
            Configured requests.Session object.
        """
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def authenticate(self) -> None:
        """
        Authenticate with Acumatica API.

        Uses OAuth 2.0 Bearer token if available, otherwise falls back to username/password authentication.
        Stores session cookies for subsequent requests.

        Raises:
            requests.exceptions.RequestException: If authentication fails.
        """
        # Try OAuth first if access token is available
        if self.config.oauth_access_token:
            logging.info(f"Authenticating with OAuth 2.0 at {self.base_url}")
            try:
                self._authenticate_oauth()
                return
            except requests.exceptions.RequestException as e:
                logging.warning(f"OAuth authentication failed: {e}. Falling back to username/password.")

        # Fallback to username/password authentication
        if self.config.acumatica_username and self.config.acumatica_password:
            logging.info(f"Authenticating with username/password at {self.base_url}")
            self._authenticate_username_password()
        else:
            raise ValueError(
                "No valid authentication method available. "
                "Please provide either OAuth credentials or username/password."
            )

    def _authenticate_oauth(self) -> None:
        """
        Authenticate using OAuth 2.0 Bearer token.

        Sets the Authorization header for subsequent requests.

        Note: Token refresh is handled automatically by Keboola's OAuth Broker in production.
        For local testing, tokens expire after 1 hour and must be manually refreshed.
        """
        # Set the Bearer token in session headers
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.config.oauth_access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        # Test the OAuth token by making a simple request
        test_url = f"{self.base_url}/entity/"
        try:
            response = self.session.get(test_url, timeout=30)
            response.raise_for_status()
            self._authenticated = True
            logging.info("Successfully authenticated with OAuth 2.0")
            logging.debug(f"Session headers: {dict(self.session.headers)}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401 and self.config.oauth_refresh_token:
                logging.warning("Access token expired, attempting to refresh...")
                try:
                    self._refresh_oauth_token()
                    # Update session header with new token and retry
                    self.session.headers.update({"Authorization": f"Bearer {self.config.oauth_access_token}"})
                    response = self.session.get(test_url, timeout=30)
                    response.raise_for_status()
                    self._authenticated = True
                    logging.info("Successfully authenticated with refreshed OAuth token")
                    return
                except Exception as refresh_error:
                    logging.error(f"Token refresh failed: {refresh_error}")
                    raise ValueError(
                        "OAuth token is invalid or expired and refresh failed. "
                        "Please get a new token using: ./scripts/oauth_helper.sh"
                    )
            elif e.response.status_code == 401:
                raise ValueError(
                    "OAuth token is invalid or expired. "
                    "In production, Keboola automatically refreshes tokens. "
                    "For local testing, please get a new token using the oauth_helper.sh script."
                )
            raise

    def _refresh_oauth_token(self) -> None:
        """
        Refresh the OAuth access token using the refresh token.

        Note: In Keboola production, token refresh is handled automatically
        by the OAuth Broker. This method is for local development/testing.
        """
        if not self.config.oauth_refresh_token:
            raise ValueError("No refresh token available")

        if not self.config.oauth_client_id or not self.config.oauth_client_secret:
            logging.warning(
                "Client ID and Secret not available for token refresh. "
                "Please get a new token using: ./scripts/oauth_helper.sh"
            )
            raise ValueError("Cannot refresh token without client credentials")

        token_url = f"{self.base_url}/identity/connect/token"

        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.config.oauth_refresh_token,
            "client_id": self.config.oauth_client_id,
            "client_secret": self.config.oauth_client_secret,
        }

        try:
            logging.debug(f"Refreshing token at: {token_url}")
            logging.debug(f"With client_id: {self.config.oauth_client_id}")
            logging.debug(f"Refresh token (first 20 chars): {self.config.oauth_refresh_token[:20]}...")

            response = requests.post(token_url, data=data, timeout=30)

            if response.status_code != 200:
                logging.error(f"Token refresh failed with status {response.status_code}")
                logging.error(f"Response: {response.text}")

            response.raise_for_status()
            token_data = response.json()

            # Update the access token in config
            self.config.oauth_access_token = token_data.get("access_token", "")
            if "refresh_token" in token_data:
                old_refresh = self.config.oauth_refresh_token[:20]
                self.config.oauth_refresh_token = token_data["refresh_token"]
                new_refresh = self.config.oauth_refresh_token[:20]
                logging.info(
                    f"Token refresh: OLD refresh_token: {old_refresh}... -> NEW refresh_token: {new_refresh}..."
                )

            logging.info("Successfully refreshed OAuth token")

            # Call callback to save new tokens to state
            if self.on_token_refresh:
                logging.info("Calling on_token_refresh callback to save new tokens")
                self.on_token_refresh()
        except requests.exceptions.RequestException as e:
            logging.error(f"Token refresh failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                logging.error(f"Response body: {e.response.text}")
                try:
                    error_data = e.response.json()
                    if error_data.get("error") == "invalid_grant":
                        raise ValueError(
                            "Refresh token is invalid or expired. "
                            "Both access_token and refresh_token need to be regenerated. "
                            "Please get new tokens using: ./scripts/oauth_helper.sh"
                        )
                except Exception:
                    pass
            raise ValueError("Failed to refresh OAuth token. Please get a new token using: ./scripts/oauth_helper.sh")

    def _authenticate_username_password(self) -> None:
        """
        Authenticate using username and password.

        Performs login and stores session cookies for subsequent requests.
        """
        login_url = f"{self.base_url}/entity/auth/login"

        login_data = {
            "name": self.config.acumatica_username,
            "password": self.config.acumatica_password,
        }

        try:
            response = self.session.post(login_url, json=login_data, timeout=30)
            response.raise_for_status()
            self._authenticated = True
            logging.info("Successfully authenticated with username/password")
        except requests.exceptions.RequestException as e:
            logging.error(f"Username/password authentication failed: {e}")
            raise

    def logout(self) -> None:
        """
        Logout from Acumatica API.

        Cleans up the session by logging out properly.
        """
        if not self._authenticated:
            return

        logout_url = f"{self.base_url}/entity/auth/logout"

        try:
            self.session.post(logout_url, timeout=30)
            self._authenticated = False
            logging.info("Successfully logged out from Acumatica")
        except requests.exceptions.RequestException as e:
            logging.warning(f"Logout warning: {e}")

    def get_entities(
        self,
        tenant_version: str,
        endpoint: str,
        expand: str = "",
        filter_expr: str = "",
        select: str = "",
        top: int = 2500,
    ) -> Iterator[dict[str, Any]]:
        """
        Retrieve entities from Acumatica endpoint with pagination.

        Uses OData parameters for filtering, selecting, and expanding related entities.
        Automatically handles pagination using $top and $skip.

        Args:
            tenant_version: Tenant and version string (e.g., 'Default/25.200.001').
            endpoint: Entity endpoint name (e.g., 'Customer', 'SalesOrder').
            expand: Related entities to expand (e.g., 'MainContact').
            filter_expr: OData filter expression.
            select: OData select expression for specific fields.
            top: Number of records per page (default: 100).

        Yields:
            Entity dictionaries from the API.

        Raises:
            RuntimeError: If not authenticated.
            requests.exceptions.RequestException: If API request fails.
        """
        if not self._authenticated:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        endpoint_url = f"{self.base_url}/entity/{tenant_version}/{endpoint}"

        skip = 0
        has_more = True

        logging.info(f"Fetching entities from {endpoint} (tenant/version: {tenant_version})")

        while has_more:
            params: dict[str, str | int] = {
                "$top": top,
                "$skip": skip,
            }

            if expand:
                params["$expand"] = expand
            if filter_expr:
                params["$filter"] = filter_expr
            if select:
                params["$select"] = select

            try:
                logging.debug(f"Request URL: {endpoint_url}")
                logging.debug(f"Request params: {params}")
                logging.debug(f"Request headers: {dict(self.session.headers)}")

                response = self.session.get(endpoint_url, params=params, timeout=60)

                # Attempt token refresh on 401 for OAuth
                if response.status_code == 401 and self.config.oauth_access_token and self.config.oauth_refresh_token:
                    logging.warning("Received 401, attempting to refresh OAuth token...")
                    try:
                        self._refresh_oauth_token()
                        # Update session header with new token and retry
                        self.session.headers.update({"Authorization": f"Bearer {self.config.oauth_access_token}"})
                        response = self.session.get(endpoint_url, params=params, timeout=60)
                    except Exception as refresh_error:
                        logging.error(f"Token refresh failed: {refresh_error}")

                response.raise_for_status()

                data = response.json()

                # Handle different response formats
                if isinstance(data, list):
                    entities = data
                elif isinstance(data, dict) and "value" in data:
                    entities = data["value"]
                else:
                    entities = [data]

                if not entities:
                    has_more = False
                    break

                logging.debug(f"Retrieved {len(entities)} entities (skip: {skip})")

                for entity in entities:
                    yield entity

                # Check if there are more records
                if len(entities) < top:
                    has_more = False
                else:
                    skip += top

            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to retrieve entities from {endpoint}: {e}")
                raise

        logging.info(f"Completed fetching entities from {endpoint}")

    def test_connection(self) -> bool:
        """
        Test the connection and authentication with Acumatica.

        Returns:
            True if connection is successful, False otherwise.
        """
        try:
            self.authenticate()
            self.logout()
            return True
        except requests.exceptions.RequestException:
            return False

    def __enter__(self) -> "AcumaticaClient":
        """Context manager entry."""
        self.authenticate()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with automatic logout."""
        self.logout()

    def get_tenant_versions(self) -> list[dict[str, str]]:
        """
        Fetch available tenant/version combinations from Acumatica /entity endpoint.

        Returns:
            List of dicts with 'label' and 'value' keys for each tenant/version.

        Raises:
            requests.exceptions.RequestException: If request fails.
        """
        entity_url = f"{self.base_url}/entity/"

        logging.info(f"Fetching tenant/version combinations from {entity_url}")

        response = requests.get(entity_url, timeout=30)
        response.raise_for_status()
        data = response.json()

        tenant_versions = set()

        for endpoint in data.get("endpoints", []):
            tenant = endpoint.get("name")
            version = endpoint.get("version")

            if tenant and version:
                tenant_versions.add(f"{tenant}/{version}")

        result = [{"label": tv, "value": tv} for tv in sorted(tenant_versions)]
        logging.info(f"Found {len(result)} tenant/version combinations")
        return result

    def get_swagger_data(self, tenant_version: str) -> dict[str, Any]:
        """
        Fetch swagger.json data for a specific tenant/version.

        Args:
            tenant_version: Tenant/version string (e.g., 'Default/25.200.001').

        Returns:
            Parsed swagger JSON data.

        Raises:
            requests.exceptions.RequestException: If request fails.
        """
        swagger_url = f"{self.base_url}/entity/{tenant_version}/swagger.json"

        logging.info(f"Fetching swagger from {swagger_url}")

        response = requests.get(swagger_url, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_endpoints(self, tenant_version: str) -> list[dict[str, str]]:
        """
        Fetch available endpoints from Acumatica swagger.json for selected tenant/version.

        Args:
            tenant_version: Tenant/version string (e.g., 'Default/25.200.001').

        Returns:
            List of dicts with 'label' and 'value' keys for each endpoint.

        Raises:
            requests.exceptions.RequestException: If request fails.
        """
        swagger_data = self.get_swagger_data(tenant_version)

        entity_names = set()

        for path, methods in swagger_data.get("paths", {}).items():
            if "get" not in methods:
                continue

            path_parts = path.strip("/").split("/")
            if not path_parts or path_parts[0].startswith("$"):
                continue

            entity_name = path_parts[0]

            is_collection_endpoint = len(path_parts) == 1 and "{" not in path

            if is_collection_endpoint:
                entity_names.add(entity_name)

        endpoints = [{"label": name, "value": name} for name in sorted(entity_names)]
        logging.info(f"Found {len(endpoints)} GET endpoints")
        return endpoints
