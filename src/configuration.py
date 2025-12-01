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
    """Configuration for Acumatica API connection."""

    acumatica_url: str
    acumatica_username: str
    acumatica_password: str


@dataclass
class Destination:
    """Configuration for destination settings."""

    output_table_name: str
    load_type: str = "full_load"
    primary_keys: str = ""


@dataclass
class EndpointConfig:
    """Configuration for a single Acumatica endpoint to extract."""

    tenant_version: str  # Format: "tenant/version" (e.g., "Default/25.200.001")
    endpoint: str
    expand: str
    filter_expr: str
    select: str
    output_table_name: str
    load_type: str
    primary_keys: str


class Configuration(BaseModel):
    """Main configuration for Acumatica extractor component."""

    # Global configuration settings
    acumatica_url: str  # Full URL including instance path (e.g., https://your-instance.acumatica.com/AcumaticaERP1)
    acumatica_username: str = Field(alias="#acumatica_username")
    acumatica_password: str = Field(alias="#acumatica_password")

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

    destination: dict = {}

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
        """Extract API-specific configuration."""
        return AcumaticaApiConfig(
            acumatica_url=self.acumatica_url,
            acumatica_username=self.acumatica_username,
            acumatica_password=self.acumatica_password,
        )

    def get_endpoint_config(self) -> EndpointConfig:
        """Extract endpoint-specific configuration."""
        dest = self.destination if self.destination else {}
        output_table_name = dest.get("output_table_name", "") or self.endpoint
        load_type = dest.get("load_type", "full_load")
        primary_keys = dest.get("primary_keys", "")

        return EndpointConfig(
            tenant_version=self.tenant_version,
            endpoint=self.endpoint,
            expand=self.expand,
            filter_expr=self.filter_expr,
            select=self.select,
            output_table_name=output_table_name,
            load_type=load_type,
            primary_keys=primary_keys,
        )

    def get_effective_page_size(self) -> int:
        """
        Get the effective page size to use for this configuration.

        Returns row_page_size if override_global_page_size is True,
        otherwise returns the global page_size.
        """
        if self.override_global_page_size:
            return self.row_page_size
        return self.page_size
