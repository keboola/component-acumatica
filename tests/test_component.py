"""
Tests for Acumatica Extractor Component.
"""

from unittest.mock import MagicMock

import pytest
from extractor_component import Component
from keboola.component.exceptions import UserException

from .conftest import read_csv, write_config

BASE_PARAMS = {
    "acumatica_url": "https://example.acumatica.com",
    "page_size": 2500,
    "debug": True,
    "endpoints": [
        {
            "enabled": True,
            "tenant_version": "Default/25.200.001",
            "endpoint": "Customer",
            "expand": "",
            "filter_expr": "",
            "select": "",
            "primary_keys": [],
        }
    ],
    "destination": {"load_type": "full_load"},
}

OAUTH_AUTHORIZATION = {
    "oauth_api": {
        "credentials": {
            "appKey": "test-key@Company",
            "#appSecret": "test-secret",
            "#data": (
                '{"access_token": "test_token", "refresh_token": "test_refresh",'
                ' "expires_in": 3600, "token_received_at": 1234567890.0,'
                ' "scope": "api offline_access", "token_type": "Bearer"}'
            ),
        }
    }
}


class TestFlattenEntity:
    def test_simple_dict_unchanged(self):
        entity = {"id": "123", "name": "Test Customer"}
        result = Component._flatten_entity(entity)
        assert result == {"id": "123", "name": "Test Customer"}

    def test_nested_dict_flattened_with_underscore(self):
        entity = {
            "id": "123",
            "name": "Test Customer",
            "contact": {"email": "test@example.com", "phone": "555-1234"},
        }
        result = Component._flatten_entity(entity)
        assert result == {
            "id": "123",
            "name": "Test Customer",
            "contact_email": "test@example.com",
            "contact_phone": "555-1234",
        }

    def test_list_values_stringified(self):
        entity = {"id": "123", "tags": ["tag1", "tag2"]}
        result = Component._flatten_entity(entity)
        assert result["id"] == "123"
        assert result["tags"] == "['tag1', 'tag2']"


class TestRun:
    def test_no_config_fails(self, monkeypatch):
        monkeypatch.setenv("KBC_DATADIR", "./non-existing-dir")
        with pytest.raises(ValueError):
            comp = Component()
            comp.run()

    def test_invalid_configuration_raises_user_exception(self, kbc_datadir):
        write_config(kbc_datadir, {"invalid": "config"})
        with pytest.raises(UserException):
            Component()

    def test_run_with_username_password(self, kbc_datadir, mocker):
        params = {**BASE_PARAMS, "acumatica_username": "admin", "#acumatica_password": "test-password"}
        write_config(kbc_datadir, params)

        mock_client = MagicMock()
        mock_client.get_entities.return_value = iter([{"CustomerID": "C001", "CustomerName": "Test Customer"}])
        mock_acumatica_client = mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        Component().run()

        mock_client.authenticate.assert_called_once()
        call_kwargs = mock_acumatica_client.call_args.kwargs
        assert call_kwargs["acumatica_username"] == "admin"
        assert call_kwargs["acumatica_password"] == "test-password"
        mock_client.get_entities.assert_called_once()
        assert (kbc_datadir / "out" / "tables" / "Customer.csv").exists()

    def test_run_with_valid_config_writes_csv(self, kbc_datadir, mocker):
        params = {**BASE_PARAMS, "acumatica_username": "test_user", "#acumatica_password": "test_pass"}
        write_config(kbc_datadir, params)

        mock_client = MagicMock()
        mock_client.get_entities.return_value = iter(
            [
                {"CustomerID": "C001", "CustomerName": "Test Customer 1"},
                {"CustomerID": "C002", "CustomerName": "Test Customer 2"},
            ]
        )
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        Component().run()

        mock_client.authenticate.assert_called_once()
        call_kwargs = mock_client.get_entities.call_args.kwargs
        assert call_kwargs["tenant_version"] == "Default/25.200.001"
        assert call_kwargs["endpoint"] == "Customer"

        rows = read_csv(kbc_datadir, "Customer")
        assert len(rows) == 2
        assert rows[0]["CustomerID"] == "C001"
        assert rows[1]["CustomerID"] == "C002"

    def test_run_with_oauth_multi_endpoint(self, kbc_datadir, mocker):
        params = {
            **BASE_PARAMS,
            "endpoints": [
                {
                    "enabled": True,
                    "tenant_version": "Default/25.200.001",
                    "endpoint": "Customer",
                    "expand": "",
                    "filter_expr": "",
                    "select": "",
                    "primary_keys": [],
                },
                {
                    "enabled": True,
                    "tenant_version": "Default/25.200.001",
                    "endpoint": "SalesOrder",
                    "expand": "",
                    "filter_expr": "",
                    "select": "",
                    "primary_keys": [],
                },
            ],
        }
        write_config(kbc_datadir, params, authorization=OAUTH_AUTHORIZATION)

        mock_client = MagicMock()
        mock_client.get_entities.side_effect = [
            iter([{"CustomerID": "C001", "CustomerName": "Test Customer"}]),
            iter([{"OrderNbr": "SO001", "CustomerID": "C001"}]),
        ]
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        Component().run()

        mock_client.authenticate.assert_called_once()
        assert mock_client.get_entities.call_count == 2
        assert (kbc_datadir / "out" / "tables" / "Customer.csv").exists()
        assert (kbc_datadir / "out" / "tables" / "SalesOrder.csv").exists()


class TestSyncActions:
    def test_list_tenant_versions(self, kbc_datadir, mocker):
        write_config(kbc_datadir, BASE_PARAMS, action="listTenantVersions", authorization=OAUTH_AUTHORIZATION)

        mock_client = MagicMock()
        mock_client.get_tenant_versions.return_value = ["Default/25.200.001", "Default/24.200.001"]
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        result = Component().list_tenant_versions()

        mock_client.get_tenant_versions.assert_called_once()
        assert result == ["Default/25.200.001", "Default/24.200.001"]

    def test_list_endpoints(self, kbc_datadir, mocker):
        write_config(kbc_datadir, BASE_PARAMS, action="listEndpoints", authorization=OAUTH_AUTHORIZATION)

        mock_client = MagicMock()
        mock_client.get_endpoints.return_value = ["Customer", "SalesOrder", "Invoice"]
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        result = Component().list_endpoints()

        mock_client.get_endpoints.assert_called_once_with("Default/25.200.001")
        assert result == ["Customer", "SalesOrder", "Invoice"]

    def test_get_output_columns(self, kbc_datadir, mocker):
        write_config(kbc_datadir, BASE_PARAMS, action="getOutputColumns", authorization=OAUTH_AUTHORIZATION)

        mock_client = MagicMock()
        mock_client.get_swagger_data.return_value = {"swagger": "2.0"}
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        mock_col1 = MagicMock()
        mock_col1.name = "CustomerID"
        mock_col1.required = True
        mock_col2 = MagicMock()
        mock_col2.name = "CustomerName"
        mock_col2.required = False

        mock_parser = MagicMock()
        mock_parser.get_entity_primary_key_candidates.return_value = [mock_col1, mock_col2]
        mocker.patch("shared.acumatica_base.SwaggerParser", return_value=mock_parser)

        result = Component().get_output_columns()

        mock_client.get_swagger_data.assert_called_once_with("Default/25.200.001")
        mock_parser.get_entity_primary_key_candidates.assert_called_once_with("Customer")
        assert result == [
            {"label": "CustomerID (required)", "value": "CustomerID"},
            {"label": "CustomerName", "value": "CustomerName"},
        ]
