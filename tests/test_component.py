"""
Tests for Acumatica Extractor Component.
"""

import csv
import json
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from keboola.component.exceptions import UserException

from component import Component


class TestComponent(unittest.TestCase):
    """Test cases for Acumatica extractor component."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data_dir = Path(__file__).parent / "test_data"
        self.test_data_dir.mkdir(exist_ok=True)
        (self.test_data_dir / "in" / "tables").mkdir(parents=True, exist_ok=True)
        (self.test_data_dir / "out" / "tables").mkdir(parents=True, exist_ok=True)
        (self.test_data_dir / "in" / "state.json").write_text("{}")

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        if self.test_data_dir.exists():
            shutil.rmtree(self.test_data_dir)

    def test_flatten_entity_simple(self):
        """Test flattening simple entity."""
        entity = {"id": "123", "name": "Test Customer"}
        result = Component._flatten_entity(entity)
        self.assertEqual(result, {"id": "123", "name": "Test Customer"})

    def test_flatten_entity_nested(self):
        """Test flattening nested entity."""
        entity = {
            "id": "123",
            "name": "Test Customer",
            "contact": {"email": "test@example.com", "phone": "555-1234"},
        }
        result = Component._flatten_entity(entity)
        expected = {
            "id": "123",
            "name": "Test Customer",
            "contact_email": "test@example.com",
            "contact_phone": "555-1234",
        }
        self.assertEqual(result, expected)

    def test_flatten_entity_with_list(self):
        """Test flattening entity with list values."""
        entity = {"id": "123", "tags": ["tag1", "tag2"]}
        result = Component._flatten_entity(entity)
        self.assertEqual(result["id"], "123")
        self.assertEqual(result["tags"], "['tag1', 'tag2']")

    @patch.dict(os.environ, {"KBC_DATADIR": "./non-existing-dir"})
    def test_run_no_config_fails(self):
        """Test that component fails without configuration."""
        with self.assertRaises(ValueError):
            comp = Component()
            comp.run()

    def _create_test_config(self) -> dict:
        """Create test configuration."""
        return {
            "parameters": {
                "acumatica_url": "https://test.acumatica.com",
                "acumatica_username": "test_user",
                "#acumatica_password": "test_pass",
                "tenant_version": "Default/23.200.001",
                "endpoint": "Customer",
                "expand": "",
                "filter_expr": "",
                "select": "",
                "override_global_page_size": False,
                "row_page_size": 2500,
                "destination": {
                    "output_table_name": "customers",
                    "load_type": "full_load",
                    "primary_keys": "",
                },
                "debug": False,
            }
        }

    @patch.dict(os.environ, {"KBC_DATADIR": str(Path(__file__).parent / "test_data")})
    @patch("component.AcumaticaClient")
    def test_run_with_valid_config(self, mock_client_class):
        """Test successful component run with valid configuration."""
        # Create test configuration
        config = self._create_test_config()
        config_path = self.test_data_dir / "config.json"
        config_path.write_text(json.dumps(config))

        # Mock the Acumatica client
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        # Mock entity data
        mock_entities = [
            {"CustomerID": "C001", "CustomerName": "Test Customer 1"},
            {"CustomerID": "C002", "CustomerName": "Test Customer 2"},
        ]
        mock_client.get_entities.return_value = iter(mock_entities)

        # Run component
        comp = Component()
        comp.run()

        # Verify client was authenticated
        mock_client.authenticate.assert_called_once()

        # Verify client was called correctly
        mock_client.get_entities.assert_called_once()
        call_args = mock_client.get_entities.call_args
        self.assertEqual(call_args.kwargs["tenant_version"], "Default/23.200.001")
        self.assertEqual(call_args.kwargs["endpoint"], "Customer")

        # Verify output file was created
        output_file = self.test_data_dir / "out" / "tables" / "customers.csv"
        self.assertTrue(output_file.exists())

        # Verify CSV content
        with open(output_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["CustomerID"], "C001")
            self.assertEqual(rows[1]["CustomerID"], "C002")

    @patch.dict(os.environ, {"KBC_DATADIR": str(Path(__file__).parent / "test_data")})
    def test_invalid_configuration(self):
        """Test that invalid configuration raises UserException."""
        config = {"parameters": {"invalid": "config"}}
        config_path = self.test_data_dir / "config.json"
        config_path.write_text(json.dumps(config))

        with self.assertRaises(UserException):
            Component()


if __name__ == "__main__":
    unittest.main()
