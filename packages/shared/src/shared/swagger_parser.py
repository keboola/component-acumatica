"""
Swagger schema parser for Acumatica API.

Handles parsing of Swagger/OpenAPI specifications to extract entity schemas
and field information for primary key selection and other metadata.
"""

import logging
from dataclasses import dataclass
from typing import Any


@dataclass
class SwaggerColumn:
    """Represents a column/field in an Acumatica entity schema."""

    name: str
    required: bool


class SwaggerParser:
    """Parser for Acumatica Swagger/OpenAPI specifications."""

    def __init__(self, swagger_data: dict[str, Any]):
        """
        Initialize parser with swagger data.

        Args:
            swagger_data: Parsed JSON swagger/OpenAPI specification.
        """
        self.swagger_data = swagger_data
        self.definitions = swagger_data.get("definitions", {})
        self.components = swagger_data.get("components", {}).get("schemas", {})

    def _extract_all_properties(self, schema: dict[str, Any]) -> dict[str, Any]:
        """
        Extract all properties from a schema, handling allOf, anyOf, oneOf.

        Args:
            schema: Schema dictionary.

        Returns:
            Combined properties dictionary.
        """
        properties = {}

        # Direct properties
        if "properties" in schema:
            properties.update(schema["properties"])

        # Handle allOf (combines multiple schemas)
        if "allOf" in schema:
            for sub_schema in schema["allOf"]:
                # Resolve $ref if present
                if "$ref" in sub_schema:
                    resolved = self._resolve_ref(sub_schema["$ref"])
                    if resolved:
                        properties.update(self._extract_all_properties(resolved))
                else:
                    properties.update(self._extract_all_properties(sub_schema))

        # Handle anyOf and oneOf similarly
        for key in ["anyOf", "oneOf"]:
            if key in schema:
                for sub_schema in schema[key]:
                    if "$ref" in sub_schema:
                        resolved = self._resolve_ref(sub_schema["$ref"])
                        if resolved:
                            properties.update(self._extract_all_properties(resolved))
                    else:
                        properties.update(self._extract_all_properties(sub_schema))

        return properties

    def _resolve_ref(self, ref: str) -> dict[str, Any] | None:
        """
        Resolve a JSON Schema $ref reference.

        Args:
            ref: Reference string (e.g., '#/components/schemas/Entity').

        Returns:
            Resolved schema or None if not found.
        """
        # Handle #/components/schemas/Name
        if ref.startswith("#/components/schemas/"):
            schema_name = ref.split("/")[-1]
            return self.components.get(schema_name)

        # Handle #/definitions/Name
        if ref.startswith("#/definitions/"):
            schema_name = ref.split("/")[-1]
            return self.definitions.get(schema_name)

        logging.warning(f"Could not resolve reference: {ref}")
        return None

    def _find_entity_schema(self, entity_name: str) -> dict[str, Any] | None:
        """
        Find entity schema in swagger definitions or components.

        Args:
            entity_name: Name of the entity.

        Returns:
            Schema dictionary or None if not found.
        """
        # Try exact match first
        if entity_name in self.definitions:
            return self.definitions[entity_name]
        if entity_name in self.components:
            return self.components[entity_name]

        # Try case-insensitive match
        entity_lower = entity_name.lower()
        for name, schema in self.definitions.items():
            if name.lower() == entity_lower:
                return schema
        for name, schema in self.components.items():
            if name.lower() == entity_lower:
                return schema

        return None

    def get_entity_primary_key_candidates(self, entity_name: str) -> list[SwaggerColumn]:
        """
        Get likely primary key candidates from entity schema.

        Prioritizes fields that commonly serve as primary keys:
        - Fields containing 'ID' in the name
        - Fields ending with 'Nbr' (common in Acumatica)
        - Fields ending with 'Number'
        - Fields marked as required

        Args:
            entity_name: Name of the entity.

        Returns:
            List of field names that are likely primary key candidates.
        """
        schema = self._find_entity_schema(entity_name)

        if not schema:
            return []

        properties = self._extract_all_properties(schema)
        required_fields = set(schema.get("required", []))

        candidates = []
        regular_fields = []

        for field_name in properties.keys():
            # Required fields are potential candidates
            if field_name in required_fields:
                candidates.append(SwaggerColumn(field_name, True))
            else:
                regular_fields.append(SwaggerColumn(field_name, False))

        # Return candidates first, then other fields; no sorting, keeping the order the same as in the response
        result = candidates + regular_fields
        logging.debug(f"Primary key candidates for {entity_name}: {candidates}")
        return result
