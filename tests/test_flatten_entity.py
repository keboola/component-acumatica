"""
Tests for Component._flatten_entity — edge cases beyond the basics in test_component.py.
"""

import pytest

from component import Component


class TestFlattenEntityEdgeCases:
    def test_empty_entity_returns_empty_dict(self):
        assert Component._flatten_entity({}) == {}

    def test_none_value_preserved(self):
        result = Component._flatten_entity({"field": None})
        assert result == {"field": None}

    def test_boolean_value_preserved(self):
        result = Component._flatten_entity({"active": True, "deleted": False})
        assert result["active"] is True
        assert result["deleted"] is False

    def test_integer_value_preserved(self):
        result = Component._flatten_entity({"count": 42})
        assert result["count"] == 42

    def test_float_value_preserved(self):
        result = Component._flatten_entity({"price": 9.99})
        assert result["price"] == 9.99

    def test_empty_dict_value_is_dropped(self):
        # isinstance(value, dict) and value → empty dict is falsy, skipped
        result = Component._flatten_entity({"contact": {}})
        assert "contact" not in result

    def test_deeply_nested_three_levels(self):
        entity = {"a": {"b": {"c": "deep"}}}
        result = Component._flatten_entity(entity)
        assert result == {"a_b_c": "deep"}

    def test_deeply_nested_four_levels(self):
        entity = {"a": {"b": {"c": {"d": "very_deep"}}}}
        result = Component._flatten_entity(entity)
        assert result == {"a_b_c_d": "very_deep"}

    def test_mixed_nested_and_flat(self):
        entity = {
            "id": "1",
            "name": "Test",
            "address": {"city": "Prague", "zip": "11000"},
            "score": 99,
        }
        result = Component._flatten_entity(entity)
        assert result["id"] == "1"
        assert result["name"] == "Test"
        assert result["address_city"] == "Prague"
        assert result["address_zip"] == "11000"
        assert result["score"] == 99

    def test_empty_list_value_stringified(self):
        result = Component._flatten_entity({"tags": []})
        assert result["tags"] == "[]"

    def test_list_of_dicts_stringified(self):
        result = Component._flatten_entity({"items": [{"id": 1}, {"id": 2}]})
        assert result["items"] == "[{'id': 1}, {'id': 2}]"

    def test_custom_separator(self):
        entity = {"a": {"b": "val"}}
        result = Component._flatten_entity(entity, sep=".")
        assert "a.b" in result
        assert result["a.b"] == "val"

    def test_parent_key_prefix_applied(self):
        entity = {"x": "val"}
        result = Component._flatten_entity(entity, parent_key="prefix")
        assert result == {"prefix_x": "val"}

    def test_parent_key_with_nested(self):
        entity = {"outer": {"inner": "val"}}
        result = Component._flatten_entity(entity, parent_key="root")
        assert result == {"root_outer_inner": "val"}

    def test_sibling_keys_not_mixed(self):
        entity = {
            "a": {"x": 1},
            "b": {"x": 2},
        }
        result = Component._flatten_entity(entity)
        assert result["a_x"] == 1
        assert result["b_x"] == 2

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("string", "string"),
            (0, 0),
            (0.0, 0.0),
            (False, False),
            (None, None),
        ],
    )
    def test_falsy_primitives_preserved(self, value, expected):
        result = Component._flatten_entity({"field": value})
        assert result["field"] == expected
