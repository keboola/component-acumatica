"""
Acumatica Writer Component.

Reads CSV input tables and upserts records into Acumatica ERP via REST API PUT.
"""

import csv
import logging
import sys
from pathlib import Path
from typing import Any

from keboola.component.base import ComponentBase
from keboola.component.exceptions import UserException
from shared.acumatica_base import AcumaticaSyncActionsMixin
from writer_configuration import Configuration, TableConfig


class Component(AcumaticaSyncActionsMixin, ComponentBase):
    """
    Acumatica Writer Component.

    Reads configured input CSV tables and upserts each row into the corresponding
    Acumatica endpoint via PUT (upsert — create or update by natural key).
    """

    def __init__(self) -> None:
        super().__init__()
        self._state: dict[str, Any] | None = None

        env = self.environment_variables
        self._component_id: str = env.component_id
        self._project_id: str = env.project_id
        self._storage_api_token: str = env.token
        self._storage_api_url: str = env.url or ""
        self._encryption_api_url: str = self._storage_api_url.replace("connection", "encryption")
        self._config_id: str = env.config_id
        self._state = self.get_state_file()

        self.config = Configuration(**self.configuration.parameters)
        self.client = self._init_client()

    def run(self) -> None:
        """Main execution - orchestrates the writer workflow."""
        try:
            logging.info("Starting Acumatica data write")

            enabled_tables = [t for t in self.config.tables if t.enabled]

            if not enabled_tables:
                raise UserException("No tables configured. Please add at least one table to write.")

            self.client.authenticate()

            try:
                for idx, table_config in enumerate(enabled_tables, 1):
                    logging.info(f"Processing table {idx}/{len(enabled_tables)}: {table_config.input_table}")
                    self._write_table(table_config)

                logging.info(f"Acumatica data write completed successfully ({len(enabled_tables)} tables)")
            finally:
                if self.client.acumatica_username and not self.client.oauth_access_token:
                    self.client.logout()

        except UserException:
            raise
        except Exception as e:
            logging.exception("Unhandled error during write")
            raise UserException(f"Write failed: {str(e)}")

    def _write_table(self, table_config: "TableConfig") -> None:
        """Read a CSV input table and upsert each row into Acumatica."""
        input_path = Path(self.tables_in_path) / table_config.input_table
        if not input_path.exists():
            raise UserException(f"Input table not found: {table_config.input_table}")

        records = self._read_csv(input_path)

        if not records:
            logging.info(f"Input table '{table_config.input_table}' is empty — nothing to write")
            return

        total = len(records)
        logging.info(f"Writing {total} records to {table_config.endpoint} ({table_config.tenant_version})")

        for i, record in enumerate(records, 1):
            logging.debug(f"Upserting record {i}/{total}")
            try:
                self.client.put_entity(
                    tenant_version=table_config.tenant_version,
                    endpoint=table_config.endpoint,
                    payload=record,
                )
            except Exception as e:
                raise UserException(f"Failed to upsert record {i} into {table_config.endpoint}: {e}")

        logging.info(f"Successfully wrote {total} records to {table_config.endpoint}")

    @staticmethod
    def _read_csv(path: Path) -> list[dict[str, Any]]:
        """
        Read CSV and return records as dicts, omitting empty values so
        Acumatica uses its field defaults.
        """
        records = []
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                record = {k: v for k, v in row.items() if v != ""}
                if record:
                    records.append(record)
        return records


"""
Main entrypoint
"""
if __name__ == "__main__":
    try:
        comp = Component()
        comp.execute_action()
    except UserException as exc:
        logging.exception(exc)
        sys.exit(1)
    except Exception as exc:
        logging.exception(exc)
        sys.exit(2)
