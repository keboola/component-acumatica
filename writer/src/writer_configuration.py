"""
Configuration schema for Acumatica Writer.

Extends shared connection configuration with write-specific fields.
"""

import logging

from pydantic import BaseModel, Field
from shared.connection import AcumaticaConnectionConfig


class TableConfig(BaseModel):
    """Configuration for a single table to write."""

    enabled: bool = True
    tenant_version: str = ""  # Format: "tenant/version" (e.g., "Default/25.200.001")
    endpoint: str = ""  # e.g., 'Customer', 'SalesOrder'
    input_table: str = ""  # Input CSV table filename (e.g., 'customers.csv')


class Configuration(AcumaticaConnectionConfig):
    """Acumatica Writer configuration — connection + write settings."""

    tables: list[TableConfig] = Field(default_factory=list)

    def __init__(self, **data):
        super().__init__(**data)

        if self.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("Component running in debug mode")
