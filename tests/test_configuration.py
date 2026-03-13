"""
Tests for the Configuration class — defaults, aliases, URL validation, and debug mode.
"""

import logging

import pytest
from configuration import Configuration, Destination, EndpointConfig
from keboola.component.exceptions import UserException

BASE_URL = "https://example.acumatica.com"


class TestUrlValidation:
    def test_valid_https_url_accepted(self):
        config = Configuration(acumatica_url="https://example.acumatica.com")
        assert config.acumatica_url == "https://example.acumatica.com"

    def test_valid_http_url_accepted(self):
        config = Configuration(acumatica_url="http://localhost/AcumaticaERP")
        assert config.acumatica_url == "http://localhost/AcumaticaERP"

    def test_trailing_slash_stripped(self):
        config = Configuration(acumatica_url="https://example.acumatica.com/")
        assert config.acumatica_url == "https://example.acumatica.com"

    def test_multiple_trailing_slashes_stripped(self):
        config = Configuration(acumatica_url="https://example.acumatica.com///")
        assert config.acumatica_url == "https://example.acumatica.com"

    def test_leading_whitespace_stripped(self):
        config = Configuration(acumatica_url="  https://example.acumatica.com")
        assert config.acumatica_url == "https://example.acumatica.com"

    def test_trailing_whitespace_stripped(self):
        config = Configuration(acumatica_url="https://example.acumatica.com  ")
        assert config.acumatica_url == "https://example.acumatica.com"

    def test_url_without_scheme_raises_user_exception(self):
        with pytest.raises(UserException):
            Configuration(acumatica_url="example.acumatica.com")

    def test_empty_url_raises_user_exception(self):
        with pytest.raises(UserException):
            Configuration(acumatica_url="")

    def test_missing_url_raises_user_exception(self):
        with pytest.raises(UserException):
            Configuration()


class TestPasswordAlias:
    def test_password_via_hash_alias(self):
        config = Configuration(acumatica_url=BASE_URL, **{"#acumatica_password": "secret"})
        assert config.acumatica_password == "secret"

    def test_password_via_direct_name(self):
        config = Configuration(acumatica_url=BASE_URL, acumatica_password="secret")
        assert config.acumatica_password == "secret"

    def test_password_defaults_to_empty(self):
        config = Configuration(acumatica_url=BASE_URL)
        assert config.acumatica_password == ""


class TestDefaults:
    @pytest.mark.parametrize(
        "field,expected",
        [
            ("acumatica_username", ""),
            ("acumatica_password", ""),
            ("page_size", 2500),
            ("debug", False),
        ],
    )
    def test_default_value(self, field, expected):
        config = Configuration(acumatica_url=BASE_URL)
        assert getattr(config, field) == expected

    def test_endpoints_default_empty_list(self):
        config = Configuration(acumatica_url=BASE_URL)
        assert config.endpoints == []

    def test_destination_default_full_load(self):
        config = Configuration(acumatica_url=BASE_URL)
        assert config.destination.load_type == "full_load"


class TestEndpointConfigDefaults:
    def test_enabled_defaults_true(self):
        ep = EndpointConfig()
        assert ep.enabled is True

    def test_string_fields_default_empty(self):
        ep = EndpointConfig()
        assert ep.tenant_version == ""
        assert ep.endpoint == ""
        assert ep.expand == ""
        assert ep.filter_expr == ""
        assert ep.select == ""

    def test_primary_keys_default_empty_list(self):
        ep = EndpointConfig()
        assert ep.primary_keys == []

    def test_primary_keys_instances_are_independent(self):
        ep1 = EndpointConfig()
        ep2 = EndpointConfig()
        ep1.primary_keys.append("id")
        assert ep2.primary_keys == []


class TestDestinationDefaults:
    def test_load_type_defaults_to_full_load(self):
        dest = Destination()
        assert dest.load_type == "full_load"

    def test_load_type_incremental_accepted(self):
        dest = Destination(load_type="incremental_load")
        assert dest.load_type == "incremental_load"


class TestValidationErrorWrapping:
    def test_invalid_field_type_raises_user_exception(self):
        with pytest.raises(UserException, match="Configuration validation error"):
            Configuration(acumatica_url=BASE_URL, page_size="not-a-number")

    def test_user_exception_message_contains_field_name(self):
        with pytest.raises(UserException, match="page_size"):
            Configuration(acumatica_url=BASE_URL, page_size="not-a-number")


class TestDebugMode:
    def test_debug_true_sets_log_level_to_debug(self):
        Configuration(acumatica_url=BASE_URL, debug=True)
        assert logging.getLogger().level == logging.DEBUG

    def test_debug_false_does_not_set_debug_level(self):
        logging.getLogger().setLevel(logging.WARNING)
        Configuration(acumatica_url=BASE_URL, debug=False)
        assert logging.getLogger().level == logging.WARNING
