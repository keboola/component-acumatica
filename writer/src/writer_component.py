"""
Acumatica Writer Component.

Reads a Keboola input table and upserts records into Acumatica ERP via REST API PUT.
"""

import csv
import logging
import sys
from pathlib import Path
from typing import Any

from keboola.component.base import sync_action
from keboola.component.exceptions import UserException
from shared.acumatica_base import AcumaticaSyncActionsMixin
from writer_configuration import Configuration, FieldMapping


class Component(AcumaticaSyncActionsMixin):
    config: Configuration  # narrows mixin's AcumaticaConnectionConfig
    """
    Acumatica Writer Component.

    Reads the configured Keboola input table, applies field mapping, and upserts
    each row into Acumatica via PUT.
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

    def _get_sync_action_endpoint(self) -> Configuration:
        """Return self.config directly — writer has flat single-endpoint config."""
        return self.config

    @sync_action("listInputTables")
    def list_input_tables(self) -> list[dict[str, str]]:
        """Return available input table destination names from the current input mapping."""
        tables = self.configuration.tables_input_mapping
        if not tables:
            raise UserException("No input tables configured in the input mapping.")
        return [{"label": t.destination, "value": t.destination} for t in tables]

    def run(self) -> None:
        """Main execution - orchestrates the writer workflow."""
        try:
            logging.info("Starting Acumatica data write")

            if not self.config.endpoint:
                raise UserException("No endpoint configured. Please select an endpoint to write.")
            if not self.config.tenant_version:
                raise UserException("No tenant/version configured. Please select a tenant/version.")
            if not self.config.table_name:
                raise UserException("No input table configured. Please set the input table name.")

            input_tables = {Path(t.full_path).name: t for t in self.get_input_tables_definitions() if t.full_path}

            self.client.authenticate()

            try:
                self._write_endpoint(input_tables)
                logging.info("Acumatica data write completed")
            finally:
                if self.client.acumatica_username and not self.client.oauth_access_token:
                    self.client.logout()

        except UserException:
            raise
        except Exception as e:
            logging.exception("Unhandled error during write")
            raise UserException(f"Write failed: {str(e)}")

    def _write_endpoint(self, input_tables: dict) -> None:
        """Read input table, apply field mapping, upsert each row into Acumatica."""
        table_name = self.config.table_name
        if table_name not in input_tables:
            raise UserException(
                f"Input table '{table_name}' not found in input mapping. "
                f"Available tables: {', '.join(input_tables.keys()) or 'none'}"
            )

        input_table = input_tables[table_name]
        records = self._read_and_map_csv(Path(input_table.full_path), self.config.field_mapping)

        if not records:
            logging.info(f"Input table '{table_name}' is empty — nothing to write")
            return

        total = len(records)
        logging.info(f"Writing {total} records to {self.config.endpoint} ({self.config.tenant_version})")

        failed_records = []
        for i, record in enumerate(records, 1):
            logging.debug(f"Upserting record {i}/{total}")
            try:
                self.client.put_entity(
                    tenant_version=self.config.tenant_version,
                    endpoint=self.config.endpoint,
                    payload=record,
                )
            except Exception as e:
                error_msg = str(e)
                logging.warning(f"Failed to upsert record {i}: {error_msg}")
                if self.config.continue_on_error:
                    failed_records.append({**record, "error_message": error_msg})
                else:
                    raise UserException(f"Failed to upsert record {i} into {self.config.endpoint}: {error_msg}")

        if failed_records:
            self._write_failed_records(failed_records, self.config.endpoint)
            logging.warning(
                f"Wrote {total - len(failed_records)}/{total} records to {self.config.endpoint}. "
                f"{len(failed_records)} failed — see failed_records.csv"
            )
        else:
            logging.info(f"Successfully wrote {total} records to {self.config.endpoint}")

    @staticmethod
    def _read_and_map_csv(path: Path, field_mapping: list[FieldMapping]) -> list[dict[str, Any]]:
        """
        Read CSV and apply field mapping.

        If field_mapping is configured, renames columns from source_column to destination_field
        and drops unmapped columns. Empty values are omitted so Acumatica uses field defaults.

        If no field_mapping is configured, passes all non-empty columns through as-is.
        """
        records = []
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            mapping = {fm.source_column: fm.destination_field for fm in field_mapping if fm.source_column}

            for row in reader:
                if mapping:
                    record = {dest: row[src] for src, dest in mapping.items() if src in row and row[src] != ""}
                else:
                    record = {k: v for k, v in row.items() if v != ""}

                if record:
                    records.append(record)

        return records

    def _write_failed_records(self, failed_records: list[dict[str, Any]], endpoint: str) -> None:
        """Write failed records to an output table for inspection."""
        if not failed_records:
            return

        table_name = f"failed_records_{endpoint}.csv"
        table = self.create_out_table_definition(name=table_name, incremental=False)
        fieldnames = list(failed_records[0].keys())

        with open(table.full_path, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(failed_records)

        self.write_manifest(table)
        logging.info(f"Failed records written to {table_name}")


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
