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
    company: str


@dataclass
class EndpointConfig:
    """Configuration for a single Acumatica endpoint to extract."""

    endpoint: str
    version: str
    expand: str
    filter: str
    select: str
    output_table: str


class Configuration(BaseModel):
    """Main configuration for Acumatica extractor component."""

    # Connection settings
    acumatica_url: str  # Full URL including instance path (e.g., https://your-instance.acumatica.com/AcumaticaERP1)
    acumatica_username: str = Field(alias="#acumatica_username")
    acumatica_password: str = Field(alias="#acumatica_password")
    company: str

    # Endpoint settings (from row config)
    # Final URL pattern: {acumatica_url}/entity/{company}/{endpoint}/{version}/
    endpoint: str  # e.g., 'Customer', 'SalesOrder'
    version: str  # API version e.g., '23.200.001'
    expand: str = ""  # OData $expand - related entities to include (e.g., 'MainContact,BillingAddress')
    filter: str = ""  # OData $filter - filter expression (e.g., "Status eq 'Active'")
    select: str = ""  # OData $select - specific fields to retrieve (e.g., 'CustomerID,CustomerName')

    output_table: str

    # Global settings
    page_size: int = 2500
    incremental_output: bool = False
    debug: bool = False

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
            company=self.company,
        )

    def get_endpoint_config(self) -> EndpointConfig:
        """Extract endpoint-specific configuration."""
        return EndpointConfig(
            endpoint=self.endpoint,
            version=self.version,
            expand=self.expand,
            filter=self.filter,
            select=self.select,
            output_table=self.output_table,
        )
