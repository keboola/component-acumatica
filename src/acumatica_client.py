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

    def __init__(self, config: AcumaticaApiConfig):
        """
        Initialize Acumatica API client.

        Args:
            config: API configuration containing URL, credentials, and company.
        """
        self.config = config
        self.base_url = config.acumatica_url
        self.session = self._create_session()
        self._authenticated = False

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

        Performs login and stores session cookies for subsequent requests.

        Raises:
            requests.exceptions.RequestException: If authentication fails.
        """
        login_url = f"{self.base_url}/entity/auth/login"

        login_data = {
            "name": self.config.acumatica_username,
            "password": self.config.acumatica_password,
            "company": self.config.company,
        }

        logging.info(f"Authenticating with Acumatica at {self.base_url}")

        try:
            response = self.session.post(login_url, json=login_data, timeout=30)
            response.raise_for_status()
            self._authenticated = True
            logging.info("Successfully authenticated with Acumatica")
        except requests.exceptions.RequestException as e:
            logging.error(f"Authentication failed: {e}")
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
        endpoint: str,
        version: str,
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
            endpoint: Entity endpoint name (e.g., 'Customer', 'SalesOrder').
            version: API version (e.g., '23.200.001').
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

        endpoint_url = (
            f"{self.base_url}/entity/{self.config.company}/{version}/{endpoint}"
        )

        skip = 0
        has_more = True

        logging.info(f"Fetching entities from {endpoint} (version: {version})")

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
                response = self.session.get(endpoint_url, params=params, timeout=60)
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
