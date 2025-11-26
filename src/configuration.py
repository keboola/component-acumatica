"""
Configuration classes for Acumatica extractor component.

Defines the structure of configuration parameters using Pydantic models.
"""

import logging
from collections.abc import Sequence

from keboola.component.exceptions import UserException
from pydantic import BaseModel, Field, ValidationError, field_validator


class EndpointConfig(BaseModel):
    """Configuration for a single Acumatica endpoint to extract."""

    endpoint: str = Field(..., description="Acumatica endpoint name (e.g., 'Customer', 'SalesOrder')")
    version: str = Field(..., description="API version (e.g., '23.200.001')")
    expand: str = Field(default="", description="Related entities to expand (e.g., 'MainContact')")
    filter: str = Field(default="", description="OData filter expression")
    select: str = Field(default="", description="OData select expression for specific fields")
    output_table: str = Field(..., description="Output table name for this endpoint")

    @field_validator("endpoint")
    @classmethod
    def endpoint_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Endpoint name cannot be empty")
        return v.strip()

    @field_validator("version")
    @classmethod
    def version_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("API version cannot be empty")
        return v.strip()

    @field_validator("output_table")
    @classmethod
    def output_table_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Output table name cannot be empty")
        return v.strip()


class AcumaticaApiConfig(BaseModel):
    """Configuration for Acumatica API connection."""

    acumatica_url: str = Field(..., description="Acumatica instance URL")
    acumatica_username: str = Field(..., alias="#acumatica_username", description="Acumatica username")
    acumatica_password: str = Field(..., alias="#acumatica_password", description="Acumatica password")
    company: str = Field(..., description="Company name in Acumatica")

    @field_validator("acumatica_url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Acumatica URL cannot be empty")
        url = v.strip()
        if not url.startswith(("http://", "https://")):
            raise ValueError("Acumatica URL must start with http:// or https://")
        return url.rstrip("/")

    @field_validator("acumatica_username")
    @classmethod
    def username_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Acumatica username cannot be empty")
        return v.strip()

    @field_validator("acumatica_password")
    @classmethod
    def password_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Acumatica password cannot be empty")
        return v

    @field_validator("company")
    @classmethod
    def company_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Company name cannot be empty")
        return v.strip()


class Configuration(BaseModel):
    """Main configuration for Acumatica extractor component."""

    acumatica_url: str = Field(..., description="Acumatica instance URL")
    acumatica_username: str = Field(..., alias="#acumatica_username", description="Acumatica username")
    acumatica_password: str = Field(..., alias="#acumatica_password", description="Acumatica password")
    company: str = Field(..., description="Company name in Acumatica")
    endpoints: Sequence[EndpointConfig] = Field(..., description="List of endpoints to extract")
    page_size: int = Field(default=2500, description="Number of records per API request", ge=1)
    incremental_output: bool = Field(default=False, description="Whether to use incremental output")
    debug: bool = Field(default=False, description="Enable debug mode")

    def __init__(self, **data):
        try:
            super().__init__(**data)
        except ValidationError as e:
            error_messages = [f"{err['loc'][0]}: {err['msg']}" for err in e.errors()]
            raise UserException(f"Configuration validation error: {', '.join(error_messages)}")

        if self.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("Component running in debug mode")

    @field_validator("endpoints")
    @classmethod
    def endpoints_not_empty(cls, v: Sequence[EndpointConfig]) -> Sequence[EndpointConfig]:
        if not v:
            raise ValueError("At least one endpoint must be configured")
        return v

    def get_api_config(self) -> AcumaticaApiConfig:
        """Extract API-specific configuration."""
        return AcumaticaApiConfig(
            acumatica_url=self.acumatica_url,
            **{"#acumatica_username": self.acumatica_username},
            **{"#acumatica_password": self.acumatica_password},
            company=self.company,
        )
