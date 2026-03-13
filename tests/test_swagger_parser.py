"""
Tests for SwaggerParser — schema loading, ref resolution, entity lookup, and column extraction.
"""

from swagger_parser import SwaggerColumn, SwaggerParser

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SWAGGER2_DATA = {
    "swagger": "2.0",
    "definitions": {
        "Customer": {
            "properties": {
                "CustomerID": {"type": "string"},
                "CustomerName": {"type": "string"},
                "Status": {"type": "string"},
            },
            "required": ["CustomerID"],
        }
    },
}

OPENAPI3_DATA = {
    "openapi": "3.0.0",
    "components": {
        "schemas": {
            "Invoice": {
                "properties": {
                    "ReferenceNbr": {"type": "string"},
                    "Amount": {"type": "number"},
                },
                "required": ["ReferenceNbr"],
            }
        }
    },
}

BOTH_DATA = {
    "swagger": "2.0",
    "definitions": {"Customer": {"properties": {"CustomerID": {}}}},
    "components": {"schemas": {"Invoice": {"properties": {"ReferenceNbr": {}}}}},
}


# ---------------------------------------------------------------------------
# TestInit
# ---------------------------------------------------------------------------


class TestInit:
    def test_swagger2_definitions_loaded(self):
        parser = SwaggerParser(SWAGGER2_DATA)
        assert "Customer" in parser.definitions
        assert parser.components == {}

    def test_openapi3_components_loaded(self):
        parser = SwaggerParser(OPENAPI3_DATA)
        assert "Invoice" in parser.components
        assert parser.definitions == {}

    def test_both_sections_loaded(self):
        parser = SwaggerParser(BOTH_DATA)
        assert "Customer" in parser.definitions
        assert "Invoice" in parser.components

    def test_empty_swagger_data(self):
        parser = SwaggerParser({})
        assert parser.definitions == {}
        assert parser.components == {}


# ---------------------------------------------------------------------------
# TestResolveRef
# ---------------------------------------------------------------------------


class TestResolveRef:
    def test_components_schemas_ref_resolved(self):
        parser = SwaggerParser(OPENAPI3_DATA)
        result = parser._resolve_ref("#/components/schemas/Invoice")
        assert result is not None
        assert "ReferenceNbr" in result["properties"]

    def test_definitions_ref_resolved(self):
        parser = SwaggerParser(SWAGGER2_DATA)
        result = parser._resolve_ref("#/definitions/Customer")
        assert result is not None
        assert "CustomerID" in result["properties"]

    def test_unknown_ref_returns_none(self, caplog):
        parser = SwaggerParser(SWAGGER2_DATA)
        result = parser._resolve_ref("#/definitions/NonExistent")
        assert result is None

    def test_unrecognized_ref_format_returns_none(self, caplog):
        parser = SwaggerParser(SWAGGER2_DATA)
        result = parser._resolve_ref("#/other/path/Thing")
        assert result is None


# ---------------------------------------------------------------------------
# TestFindEntitySchema
# ---------------------------------------------------------------------------


class TestFindEntitySchema:
    def test_exact_match_in_definitions(self):
        parser = SwaggerParser(SWAGGER2_DATA)
        schema = parser._find_entity_schema("Customer")
        assert schema is not None
        assert "CustomerID" in schema["properties"]

    def test_exact_match_in_components(self):
        parser = SwaggerParser(OPENAPI3_DATA)
        schema = parser._find_entity_schema("Invoice")
        assert schema is not None
        assert "ReferenceNbr" in schema["properties"]

    def test_case_insensitive_match_in_definitions(self):
        parser = SwaggerParser(SWAGGER2_DATA)
        assert parser._find_entity_schema("customer") is not None
        assert parser._find_entity_schema("CUSTOMER") is not None

    def test_case_insensitive_match_in_components(self):
        parser = SwaggerParser(OPENAPI3_DATA)
        assert parser._find_entity_schema("invoice") is not None

    def test_not_found_returns_none(self):
        parser = SwaggerParser(SWAGGER2_DATA)
        assert parser._find_entity_schema("NonExistent") is None


# ---------------------------------------------------------------------------
# TestExtractAllProperties
# ---------------------------------------------------------------------------


class TestExtractAllProperties:
    def test_direct_properties(self):
        parser = SwaggerParser({})
        schema = {"properties": {"FieldA": {}, "FieldB": {}}}
        result = parser._extract_all_properties(schema)
        assert set(result.keys()) == {"FieldA", "FieldB"}

    def test_empty_schema_returns_empty(self):
        parser = SwaggerParser({})
        assert parser._extract_all_properties({}) == {}

    def test_allof_with_ref(self):
        data = {
            "definitions": {
                "Base": {"properties": {"BaseField": {}}},
            }
        }
        parser = SwaggerParser(data)
        schema = {"allOf": [{"$ref": "#/definitions/Base"}, {"properties": {"ExtraField": {}}}]}
        result = parser._extract_all_properties(schema)
        assert "BaseField" in result
        assert "ExtraField" in result

    def test_allof_inline_schemas_merged(self):
        parser = SwaggerParser({})
        schema = {
            "allOf": [
                {"properties": {"FieldA": {}}},
                {"properties": {"FieldB": {}}},
            ]
        }
        result = parser._extract_all_properties(schema)
        assert set(result.keys()) == {"FieldA", "FieldB"}

    def test_anyof_properties_merged(self):
        parser = SwaggerParser({})
        schema = {
            "anyOf": [
                {"properties": {"FieldA": {}}},
                {"properties": {"FieldB": {}}},
            ]
        }
        result = parser._extract_all_properties(schema)
        assert "FieldA" in result
        assert "FieldB" in result

    def test_oneof_properties_merged(self):
        parser = SwaggerParser({})
        schema = {
            "oneOf": [
                {"properties": {"FieldA": {}}},
                {"properties": {"FieldB": {}}},
            ]
        }
        result = parser._extract_all_properties(schema)
        assert "FieldA" in result
        assert "FieldB" in result

    def test_allof_with_unresolvable_ref_skipped(self):
        parser = SwaggerParser({})
        schema = {"allOf": [{"$ref": "#/definitions/Missing"}, {"properties": {"FieldA": {}}}]}
        result = parser._extract_all_properties(schema)
        # Missing ref is skipped, but inline properties are still collected
        assert "FieldA" in result

    def test_nested_allof_resolved_recursively(self):
        data = {
            "definitions": {
                "GrandParent": {"properties": {"GrandField": {}}},
                "Parent": {"allOf": [{"$ref": "#/definitions/GrandParent"}, {"properties": {"ParentField": {}}}]},
            }
        }
        parser = SwaggerParser(data)
        schema = {"allOf": [{"$ref": "#/definitions/Parent"}, {"properties": {"ChildField": {}}}]}
        result = parser._extract_all_properties(schema)
        assert "GrandField" in result
        assert "ParentField" in result
        assert "ChildField" in result


# ---------------------------------------------------------------------------
# TestGetEntityPrimaryKeyCandidates
# ---------------------------------------------------------------------------


class TestGetEntityPrimaryKeyCandidates:
    def test_entity_not_found_returns_empty_list(self):
        parser = SwaggerParser(SWAGGER2_DATA)
        result = parser.get_entity_primary_key_candidates("NonExistent")
        assert result == []

    def test_returns_list_of_swagger_columns(self):
        parser = SwaggerParser(SWAGGER2_DATA)
        result = parser.get_entity_primary_key_candidates("Customer")
        assert all(isinstance(col, SwaggerColumn) for col in result)

    def test_required_fields_come_first(self):
        parser = SwaggerParser(SWAGGER2_DATA)
        result = parser.get_entity_primary_key_candidates("Customer")
        required = [col for col in result if col.required]
        optional = [col for col in result if not col.required]
        # All required fields appear before any optional field
        assert result.index(required[-1]) < result.index(optional[0])

    def test_required_flag_correct(self):
        parser = SwaggerParser(SWAGGER2_DATA)
        result = parser.get_entity_primary_key_candidates("Customer")
        by_name = {col.name: col for col in result}
        assert by_name["CustomerID"].required is True
        assert by_name["CustomerName"].required is False
        assert by_name["Status"].required is False

    def test_all_required_fields(self):
        data = {
            "definitions": {
                "Order": {
                    "properties": {"OrderNbr": {}, "CustomerID": {}},
                    "required": ["OrderNbr", "CustomerID"],
                }
            }
        }
        parser = SwaggerParser(data)
        result = parser.get_entity_primary_key_candidates("Order")
        assert all(col.required for col in result)
        assert {col.name for col in result} == {"OrderNbr", "CustomerID"}

    def test_no_required_fields(self):
        data = {
            "definitions": {
                "Vendor": {
                    "properties": {"VendorID": {}, "VendorName": {}},
                    # no "required" key
                }
            }
        }
        parser = SwaggerParser(data)
        result = parser.get_entity_primary_key_candidates("Vendor")
        assert all(not col.required for col in result)
        assert {col.name for col in result} == {"VendorID", "VendorName"}

    def test_schema_with_no_properties_returns_empty(self):
        data = {"definitions": {"Empty": {}}}
        parser = SwaggerParser(data)
        result = parser.get_entity_primary_key_candidates("Empty")
        assert result == []

    def test_properties_via_allof_included(self):
        data = {
            "definitions": {
                "Base": {"properties": {"BaseID": {}}, "required": ["BaseID"]},
                "Child": {"allOf": [{"$ref": "#/definitions/Base"}, {"properties": {"ChildField": {}}}]},
            }
        }
        parser = SwaggerParser(data)
        result = parser.get_entity_primary_key_candidates("Child")
        names = {col.name for col in result}
        assert "BaseID" in names
        assert "ChildField" in names
