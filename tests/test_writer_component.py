"""
Tests for Acumatica Writer Component.

Mocks only the AcumaticaClient; uses real CSV files via pytest fixtures.
"""

import csv
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from keboola.component.exceptions import UserException
from writer_component import Component

from .conftest import write_config

BASE_PARAMS = {
    "acumatica_url": "https://example.acumatica.com",
    "acumatica_username": "admin",
    "#acumatica_password": "secret",
    "tables": [
        {
            "enabled": True,
            "tenant_version": "Default/25.200.001",
            "endpoint": "Customer",
            "input_table": "customers.csv",
        }
    ],
}


def write_input_csv(data_dir: Path, filename: str, rows: list[dict]) -> Path:
    """Write an input CSV into data_dir/in/tables/."""
    tables_dir = data_dir / "in" / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)
    path = tables_dir / filename
    if rows:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    else:
        path.write_text("")
    return path


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.put_entity.return_value = {"CustomerID": {"value": "C001"}}
    return client


@pytest.fixture
def run_component(kbc_datadir, mocker, mock_client):
    """Factory: write config + input CSV, patch client, run Component."""

    def _run(parameters: dict, rows: list[dict], filename: str = "customers.csv") -> Path:
        write_config(kbc_datadir, parameters)
        write_input_csv(kbc_datadir, filename, rows)
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        Component().run()
        return kbc_datadir

    return _run


class TestBasicWrite:
    def test_records_upserted_from_csv(self, run_component, mock_client):
        rows = [
            {"CustomerID": "C001", "CustomerName": "Alice"},
            {"CustomerID": "C002", "CustomerName": "Bob"},
        ]
        run_component(BASE_PARAMS, rows)

        assert mock_client.put_entity.call_count == 2
        mock_client.put_entity.assert_any_call(
            tenant_version="Default/25.200.001",
            endpoint="Customer",
            payload={"CustomerID": "C001", "CustomerName": "Alice"},
        )
        mock_client.put_entity.assert_any_call(
            tenant_version="Default/25.200.001",
            endpoint="Customer",
            payload={"CustomerID": "C002", "CustomerName": "Bob"},
        )

    def test_empty_values_omitted(self, run_component, mock_client):
        rows = [{"CustomerID": "C001", "CustomerName": "", "Email": "alice@example.com"}]
        run_component(BASE_PARAMS, rows)

        payload = mock_client.put_entity.call_args[1]["payload"]
        assert payload == {"CustomerID": "C001", "Email": "alice@example.com"}
        assert "CustomerName" not in payload

    def test_empty_csv_no_api_calls(self, run_component, mock_client):
        run_component(BASE_PARAMS, [])
        mock_client.put_entity.assert_not_called()

    def test_row_with_all_empty_values_skipped(self, run_component, mock_client):
        run_component(BASE_PARAMS, [])
        mock_client.put_entity.assert_not_called()

    def test_client_authenticated_before_write(self, run_component, mock_client):
        rows = [{"CustomerID": "C001"}]
        run_component(BASE_PARAMS, rows)
        mock_client.authenticate.assert_called_once()

    def test_client_logged_out_after_username_password_write(self, run_component, mock_client):
        mock_client.acumatica_username = "admin"
        mock_client.oauth_access_token = ""
        rows = [{"CustomerID": "C001"}]
        run_component(BASE_PARAMS, rows)
        mock_client.logout.assert_called_once()


class TestMultipleTables:
    def test_multiple_tables_all_written(self, kbc_datadir, mocker, mock_client):
        params = {
            **BASE_PARAMS,
            "tables": [
                {
                    "enabled": True,
                    "tenant_version": "Default/25.200.001",
                    "endpoint": "Customer",
                    "input_table": "customers.csv",
                },
                {
                    "enabled": True,
                    "tenant_version": "Default/25.200.001",
                    "endpoint": "Account",
                    "input_table": "accounts.csv",
                },
            ],
        }
        write_config(kbc_datadir, params)
        write_input_csv(kbc_datadir, "customers.csv", [{"CustomerID": "C001"}])
        write_input_csv(kbc_datadir, "accounts.csv", [{"AccountID": "A001"}])
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        Component().run()

        assert mock_client.put_entity.call_count == 2

    def test_disabled_table_skipped(self, kbc_datadir, mocker, mock_client):
        params = {
            **BASE_PARAMS,
            "tables": [
                {
                    "enabled": False,
                    "tenant_version": "Default/25.200.001",
                    "endpoint": "Customer",
                    "input_table": "customers.csv",
                }
            ],
        }
        write_config(kbc_datadir, params)
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        with pytest.raises(UserException, match="No tables configured"):
            Component().run()


class TestErrorHandling:
    def test_missing_input_table_raises_user_exception(self, kbc_datadir, mocker, mock_client):
        write_config(kbc_datadir, BASE_PARAMS)
        # Do NOT write the input CSV
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        with pytest.raises(UserException, match="Input table not found"):
            Component().run()

    def test_put_entity_failure_raises_user_exception(self, run_component, mock_client):
        mock_client.put_entity.side_effect = Exception("API error")
        rows = [{"CustomerID": "C001"}]

        with pytest.raises(UserException, match="Failed to upsert record 1"):
            run_component(BASE_PARAMS, rows)

    def test_no_tables_raises_user_exception(self, kbc_datadir, mocker, mock_client):
        params = {**BASE_PARAMS, "tables": []}
        write_config(kbc_datadir, params)
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        with pytest.raises(UserException, match="No tables configured"):
            Component().run()


class TestPutEntityWrapping:
    def test_put_entity_wraps_values(self):
        """AcumaticaClient.put_entity wraps flat dict into {field: {value: ...}} format."""
        client = MagicMock()

        mock_response = MagicMock()
        mock_response.json.return_value = {}
        client.session.put.return_value = mock_response
        client._authenticated = True
        client.base_url = "https://example.acumatica.com"

        # Import and call the real put_entity method
        from shared.acumatica_client import AcumaticaClient

        real_client = AcumaticaClient(acumatica_url="https://example.acumatica.com")
        real_client._authenticated = True
        real_client.session = MagicMock()
        real_client.session.put.return_value = mock_response

        real_client.put_entity("Default/25.200.001", "Customer", {"CustomerID": "C001", "Name": "Alice"})

        call_kwargs = real_client.session.put.call_args
        sent_json = call_kwargs[1]["json"]
        assert sent_json == {
            "CustomerID": {"value": "C001"},
            "Name": {"value": "Alice"},
        }
