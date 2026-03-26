"""
Tests for Acumatica Writer Component.

Mocks only the AcumaticaClient; uses real CSV files and Keboola input table definitions.
"""

import csv
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from keboola.component.exceptions import UserException
from writer_component import Component

from ..conftest import write_config

BASE_PARAMS: dict[str, Any] = {
    "acumatica_url": "https://example.acumatica.com",
    "acumatica_username": "admin",
    "#acumatica_password": "secret",
    "tenant_version": "Default/25.200.001",
    "endpoint": "Customer",
    "table_name": "customers.csv",
    "field_mapping": [
        {"source_column": "CustomerID", "destination_field": "CustomerID"},
        {"source_column": "CustomerName", "destination_field": "CustomerName"},
    ],
    "continue_on_error": False,
}


def write_input_csv(data_dir: Path, filename: str, rows: list[dict]) -> Path:
    """Write an input CSV into data_dir/in/tables/ with a manifest."""
    tables_dir = data_dir / "in" / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)
    path = tables_dir / filename
    if rows:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    else:
        path.write_text("CustomerID,CustomerName\n")
    return path


def write_input_manifest(data_dir: Path, filename: str) -> None:
    """Write a minimal input table manifest."""
    manifest = {
        "destination": filename,
        "columns": [],
        "primary_key": [],
        "incremental": False,
    }
    manifest_path = data_dir / "in" / "tables" / f"{filename}.manifest"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.put_entity.return_value = {"CustomerID": {"value": "C001"}}
    client.acumatica_username = ""
    client.oauth_access_token = "token"
    return client


@pytest.fixture
def run_component(kbc_datadir, mocker, mock_client):
    """Factory: write config + input CSV + manifest, patch client, run Component."""

    def _run(
        parameters: dict,
        rows: list[dict],
        filename: str = "customers.csv",
    ) -> Path:
        write_config(kbc_datadir, parameters)
        write_input_csv(kbc_datadir, filename, rows)
        write_input_manifest(kbc_datadir, filename)
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        Component().run()
        return kbc_datadir

    return _run


class TestBasicWrite:
    def test_records_upserted_with_field_mapping(self, run_component, mock_client):
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

    def test_field_mapping_renames_columns(self, kbc_datadir, mocker, mock_client):
        params = {
            **BASE_PARAMS,
            "field_mapping": [
                {"source_column": "id", "destination_field": "CustomerID"},
                {"source_column": "name", "destination_field": "CustomerName"},
            ],
        }
        write_config(kbc_datadir, params)
        write_input_csv(kbc_datadir, "customers.csv", [{"id": "C001", "name": "Alice"}])
        write_input_manifest(kbc_datadir, "customers.csv")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        Component().run()

        payload = mock_client.put_entity.call_args[1]["payload"]
        assert payload == {"CustomerID": "C001", "CustomerName": "Alice"}

    def test_unmapped_columns_excluded(self, kbc_datadir, mocker, mock_client):
        params = {
            **BASE_PARAMS,
            "field_mapping": [
                {"source_column": "CustomerID", "destination_field": "CustomerID"},
            ],
        }
        write_config(kbc_datadir, params)
        write_input_csv(kbc_datadir, "customers.csv", [{"CustomerID": "C001", "Unwanted": "x"}])
        write_input_manifest(kbc_datadir, "customers.csv")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        Component().run()

        payload = mock_client.put_entity.call_args[1]["payload"]
        assert payload == {"CustomerID": "C001"}
        assert "Unwanted" not in payload

    def test_empty_values_omitted(self, run_component, mock_client):
        rows = [{"CustomerID": "C001", "CustomerName": ""}]
        run_component(BASE_PARAMS, rows)

        payload = mock_client.put_entity.call_args[1]["payload"]
        assert "CustomerName" not in payload
        assert payload["CustomerID"] == "C001"

    def test_no_field_mapping_passes_all_columns(self, kbc_datadir, mocker, mock_client):
        params = {**BASE_PARAMS, "field_mapping": []}
        write_config(kbc_datadir, params)
        write_input_csv(kbc_datadir, "customers.csv", [{"CustomerID": "C001", "CustomerName": "Alice"}])
        write_input_manifest(kbc_datadir, "customers.csv")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        Component().run()

        payload = mock_client.put_entity.call_args[1]["payload"]
        assert payload == {"CustomerID": "C001", "CustomerName": "Alice"}

    def test_empty_csv_no_api_calls(self, run_component, mock_client):
        run_component(BASE_PARAMS, [])
        mock_client.put_entity.assert_not_called()

    def test_client_authenticated_before_write(self, run_component, mock_client):
        rows = [{"CustomerID": "C001", "CustomerName": "Alice"}]
        run_component(BASE_PARAMS, rows)
        mock_client.authenticate.assert_called_once()

    def test_client_logged_out_after_username_password_write(self, run_component, mock_client):
        mock_client.acumatica_username = "admin"
        mock_client.oauth_access_token = ""
        rows = [{"CustomerID": "C001", "CustomerName": "Alice"}]
        run_component(BASE_PARAMS, rows)
        mock_client.logout.assert_called_once()


class TestErrorHandling:
    def test_missing_input_table_raises_user_exception(self, kbc_datadir, mocker, mock_client):
        write_config(kbc_datadir, BASE_PARAMS)
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        with pytest.raises(UserException, match="Input table 'customers.csv' not found"):
            Component().run()

    def test_put_entity_failure_raises_user_exception(self, run_component, mock_client):
        mock_client.put_entity.side_effect = Exception("API error")
        rows = [{"CustomerID": "C001", "CustomerName": "Alice"}]

        with pytest.raises(UserException, match="Failed to upsert record 1"):
            run_component(BASE_PARAMS, rows)

    def test_no_endpoint_raises_user_exception(self, kbc_datadir, mocker, mock_client):
        params = {**BASE_PARAMS, "endpoint": ""}
        write_config(kbc_datadir, params)
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        with pytest.raises(UserException, match="No endpoint configured"):
            Component().run()

    def test_no_table_name_raises_user_exception(self, kbc_datadir, mocker, mock_client):
        params = {**BASE_PARAMS, "table_name": ""}
        write_config(kbc_datadir, params)
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        with pytest.raises(UserException, match="No input table configured"):
            Component().run()


class TestContinueOnError:
    def test_failed_records_written_to_output_table(self, kbc_datadir, mocker, mock_client):
        params = {**BASE_PARAMS, "continue_on_error": True}
        write_config(kbc_datadir, params)
        write_input_csv(
            kbc_datadir,
            "customers.csv",
            [
                {"CustomerID": "C001", "CustomerName": "Alice"},
                {"CustomerID": "C002", "CustomerName": "Bob"},
            ],
        )
        write_input_manifest(kbc_datadir, "customers.csv")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        mock_client.put_entity.side_effect = [None, Exception("API error")]

        Component().run()

        failed_csv = kbc_datadir / "out" / "tables" / "failed_records_Customer.csv"
        assert failed_csv.exists()
        with open(failed_csv) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["CustomerID"] == "C002"
        assert "API error" in rows[0]["error_message"]

    def test_continue_on_error_false_stops_on_first_failure(self, run_component, mock_client):
        mock_client.put_entity.side_effect = [None, Exception("API error")]
        rows = [
            {"CustomerID": "C001", "CustomerName": "Alice"},
            {"CustomerID": "C002", "CustomerName": "Bob"},
        ]

        with pytest.raises(UserException, match="Failed to upsert record 2"):
            run_component(BASE_PARAMS, rows)


class TestPutEntityWrapping:
    def test_put_entity_wraps_values(self):
        """AcumaticaClient.put_entity wraps flat dict into {field: {value: ...}} format."""
        from shared.acumatica_client import AcumaticaClient

        mock_response = MagicMock()
        mock_response.json.return_value = {}

        real_client = AcumaticaClient(acumatica_url="https://example.acumatica.com")
        real_client._authenticated = True
        real_client.session = MagicMock()
        real_client.session.put.return_value = mock_response

        real_client.put_entity("Default/25.200.001", "Customer", {"CustomerID": "C001", "Name": "Alice"})

        sent_json = real_client.session.put.call_args[1]["json"]
        assert sent_json == {
            "CustomerID": {"value": "C001"},
            "Name": {"value": "Alice"},
        }


class TestFuzzyMapping:
    def test_exact_match(self):
        from shared.acumatica_base import AcumaticaSyncActionsMixin

        result = AcumaticaSyncActionsMixin._fuzzy_match_columns(["CustomerID", "Name"], ["CustomerID", "Name", "Email"])
        assert result[0] == {"source_column": "CustomerID", "destination_field": "CustomerID"}
        assert result[1] == {"source_column": "Name", "destination_field": "Name"}

    def test_case_insensitive_match(self):
        from shared.acumatica_base import AcumaticaSyncActionsMixin

        result = AcumaticaSyncActionsMixin._fuzzy_match_columns(["customerid"], ["CustomerID"])
        assert result[0]["destination_field"] == "CustomerID"

    def test_normalized_match(self):
        from shared.acumatica_base import AcumaticaSyncActionsMixin

        result = AcumaticaSyncActionsMixin._fuzzy_match_columns(["customer_id"], ["CustomerID"])
        assert result[0]["destination_field"] == "CustomerID"

    def test_unmatched_column_gets_empty_destination(self):
        from shared.acumatica_base import AcumaticaSyncActionsMixin

        result = AcumaticaSyncActionsMixin._fuzzy_match_columns(["Unknown"], ["CustomerID"])
        assert result[0] == {"source_column": "Unknown", "destination_field": ""}


class TestListInputTables:
    def test_returns_destinations_from_input_mapping(self, kbc_datadir, mocker, mock_client):
        config = {
            "action": "run",
            "parameters": BASE_PARAMS,
            "storage": {
                "input": {
                    "tables": [
                        {"source": "in.c-test.Customer", "destination": "customers.csv"},
                        {"source": "in.c-test.Account", "destination": "accounts.csv"},
                    ]
                }
            },
        }
        (kbc_datadir / "config.json").write_text(json.dumps(config))
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        result = Component().list_input_tables()

        assert result == [
            {"label": "customers.csv", "value": "customers.csv"},
            {"label": "accounts.csv", "value": "accounts.csv"},
        ]

    def test_no_input_tables_raises_user_exception(self, kbc_datadir, mocker, mock_client):
        write_config(kbc_datadir, BASE_PARAMS)
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)

        with pytest.raises(UserException, match="No input tables configured"):
            Component().list_input_tables()
