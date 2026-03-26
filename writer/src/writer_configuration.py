"""
Configuration schema for Acumatica Writer.

Extends shared connection configuration with write-specific fields.
"""

import logging

from pydantic import BaseModel, Field
from shared.connection import AcumaticaConnectionConfig


class FieldMapping(BaseModel):
    """Maps a source CSV column to an Acumatica API destination field."""

    source_column: str = ""
    destination_field: str = ""


class Configuration(AcumaticaConnectionConfig):
    """Acumatica Writer configuration — single endpoint + write settings."""

    tenant_version: str = ""  # Format: "tenant/version" (e.g., "Default/25.200.001")
    endpoint: str = ""  # e.g., 'Customer', 'SalesOrder'
    table_name: str = ""  # Destination name matching Keboola input table mapping
    field_mapping: list[FieldMapping] = Field(default_factory=list)
    continue_on_error: bool = False

    def __init__(self, **data):
        super().__init__(**data)

        if self.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("Component running in debug mode")
