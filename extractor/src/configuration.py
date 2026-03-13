"""
Configuration classes for Acumatica extractor component.

Defines the structure of configuration parameters using Pydantic models.
"""

import logging

from pydantic import BaseModel, Field
from shared.connection import AcumaticaConnectionConfig


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


class Configuration(AcumaticaConnectionConfig):
    """Main configuration for Acumatica extractor component."""

    # Endpoints to extract
    endpoints: list[EndpointConfig] = Field(default_factory=list)

    # Destination settings (shared across all endpoints)
    destination: Destination = Field(default_factory=Destination)

    def __init__(self, **data):
        super().__init__(**data)

        if self.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("Component running in debug mode")
