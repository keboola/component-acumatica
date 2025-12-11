"""
Configuration classes for Acumatica extractor component.

Defines the structure of configuration parameters using Pydantic models.
"""

import logging
from dataclasses import dataclass

from keboola.component.exceptions import UserException
from pydantic import BaseModel, Field, ValidationError, field_validator


@dataclass
class AcumaticaApiConfig:
    """Configuration for Acumatica API connection (internal use only)."""

    acumatica_url: str
    acumatica_username: str = ""
    acumatica_password: str = ""
    oauth_access_token: str = ""
    oauth_refresh_token: str = ""
    oauth_client_id: str = ""
    oauth_client_secret: str = ""


class Destination(BaseModel):
    """Configuration for destination settings."""

    output_table_name: str = ""
    load_type: str = "full_load"
    primary_keys: str = ""


class Configuration(BaseModel):
    """Main configuration for Acumatica extractor component."""

    # Global configuration settings
    acumatica_url: str  # Full URL including instance path (e.g., https://your-instance.acumatica.com/AcumaticaERP1)
    acumatica_username: str = ""
    acumatica_password: str = Field(default="", alias="#acumatica_password")

    page_size: int = 2500
    debug: bool = False

    # Configuration row settings
    # Final URL pattern: {acumatica_url}/entity/{tenant}/{version}/{endpoint}
    tenant_version: str  # Format: "tenant/version" (e.g., "Default/25.200.001")
    endpoint: str  # e.g., 'Customer', 'SalesOrder'
    expand: str = ""  # OData $expand - related entities to include (e.g., 'MainContact,BillingAddress')
    filter_expr: str = ""  # OData $filter - filter expression (e.g., "Status eq 'Active'")
    select: str = ""  # OData $select - specific fields to retrieve (e.g., 'CustomerID,CustomerName')

    override_global_page_size: bool = False
    row_page_size: int = 2500

    destination: Destination = Field(default_factory=Destination)

    def __init__(self, **data):
        try:
            super().__init__(**data)
        except ValidationError as e:
            error_messages = [f"{err['loc'][0]}: {err['msg']}" for err in e.errors()]
            raise UserException(f"Configuration validation error: {', '.join(error_messages)}")

        if self.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("Component running in debug mode")

    @field_validator("acumatica_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        url = v.strip()
        if not url.startswith(("http://", "https://")):
            raise ValueError("Acumatica URL must start with http:// or https://")
        return url.rstrip("/")

    def get_api_config(self) -> AcumaticaApiConfig:
        """Extract API-specific configuration for username/password auth."""
        return AcumaticaApiConfig(
            acumatica_url=self.acumatica_url,
            acumatica_username=self.acumatica_username,
            acumatica_password=self.acumatica_password,
            oauth_access_token="",
            oauth_refresh_token="",
            oauth_client_id="",
            oauth_client_secret="",
        )

    def get_oauth_api_config(self, oauth_credentials) -> AcumaticaApiConfig:
        """Extract API-specific configuration with OAuth credentials.

        Args:
            oauth_credentials: OauthCredentials object from keboola.component.dao
                              Contains .data dict with OAuth token response
        """
        oauth_data = oauth_credentials.data if oauth_credentials else {}
        return AcumaticaApiConfig(
            acumatica_url=self.acumatica_url,
            acumatica_username="",
            acumatica_password="",
            oauth_access_token=oauth_data.get("access_token", ""),
            oauth_refresh_token=oauth_data.get("refresh_token", ""),
            oauth_client_id=oauth_data.get("client_id", ""),
            oauth_client_secret=oauth_data.get("client_secret", ""),
        )

    def get_output_table_name(self) -> str:
        """Get the output table name, defaulting to endpoint name if not specified."""
        return self.destination.output_table_name or self.endpoint

    def get_load_type(self) -> str:
        """Get the load type from destination settings."""
        return self.destination.load_type

    def is_incremental(self) -> bool:
        """Check if the load type is incremental."""
        return self.destination.load_type == "incremental_load"

    def get_effective_page_size(self) -> int:
        """
        Get the effective page size to use for this configuration.

        Returns row_page_size if override_global_page_size is True,
        otherwise returns the global page_size.
        """
        if self.override_global_page_size:
            return self.row_page_size
        return self.page_size
