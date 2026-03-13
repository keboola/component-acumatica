"""
Shared Acumatica connection configuration.

Contains connection fields used by both extractor and writer components.
"""

from typing import Any

from keboola.component.exceptions import UserException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class AcumaticaConnectionConfig(BaseModel):
    """Shared Acumatica connection configuration — URL, credentials, page size."""

    model_config = ConfigDict(populate_by_name=True)

    acumatica_url: str
    acumatica_username: str = ""
    acumatica_password: str = Field(default="", alias="#acumatica_password")
    page_size: int = 2500
    debug: bool = False

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError as e:
            error_messages = [f"{err['loc'][0]}: {err['msg']}" for err in e.errors()]
            raise UserException(f"Configuration validation error: {', '.join(error_messages)}")

    @field_validator("acumatica_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        url = v.strip()
        if not url.startswith(("http://", "https://")):
            raise ValueError("Acumatica URL must start with http:// or https://")
        return url.rstrip("/")
