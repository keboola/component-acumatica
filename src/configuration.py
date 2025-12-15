"""
Configuration classes for Acumatica extractor component.

Defines the structure of configuration parameters using Pydantic models.
"""

import logging

from keboola.component.exceptions import UserException
from pydantic import BaseModel, Field, ValidationError, field_validator


class Destination(BaseModel):
    """Configuration for destination settings."""

    load_type: str = "full_load"


class EndpointConfig(BaseModel):
    """Configuration for a single endpoint extraction."""

    enabled: bool = True  # Whether this endpoint is enabled for extraction
    tenant_version: str = ""  # Format: "tenant/version" (e.g., "Default/25.200.001")
    endpoint: str = ""  # e.g., 'Customer', 'SalesOrder'
    expand: str = ""  # OData $expand - related entities to include
    filter_expr: str = ""  # OData $filter - filter expression
    select: str = ""  # OData $select - specific fields to retrieve
    primary_keys: list[str] = Field(default_factory=list)  # Primary keys for this endpoint


class Configuration(BaseModel):
    """Main configuration for Acumatica extractor component."""

    # Global configuration settings
    acumatica_url: str  # Full URL including instance path
    acumatica_username: str = ""
    acumatica_password: str = Field(default="", alias="#acumatica_password")

    page_size: int = 2500
    debug: bool = False

    # Endpoints to extract
    endpoints: list[EndpointConfig] = Field(default_factory=list)

    # Destination settings (shared across all endpoints)
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
