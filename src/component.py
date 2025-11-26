"""
Acumatica Extractor Component.

Extracts data from Acumatica ERP system via REST API and saves to Keboola tables.
"""

import csv
import logging
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from keboola.component.base import ComponentBase
from keboola.component.exceptions import UserException

from acumatica_client import AcumaticaClient
from configuration import Configuration, EndpointConfig


class Component(ComponentBase):
    """
    Acumatica Extractor Component.

    Extracts data from configured Acumatica endpoints and writes to output tables.
    """

    def __init__(self):
        super().__init__()

    def run(self) -> None:
        """Main execution - orchestrates the component workflow."""
        try:
            config = self._validate_and_get_configuration()
            state = self._load_previous_state()

            logging.info("Starting Acumatica data extraction")

            with AcumaticaClient(config.get_api_config()) as client:
                for endpoint_config in config.endpoints:
                    self._extract_endpoint(
                        client, endpoint_config, config.incremental_output, config.page_size
                    )

            self._update_state(state)
            logging.info("Acumatica data extraction completed successfully")

        except UserException:
            raise
        except Exception as e:
            logging.exception("Unhandled error during extraction")
            raise UserException(f"Extraction failed: {str(e)}")

    def _validate_and_get_configuration(self) -> Configuration:
        """
        Validate and parse component configuration.

        Returns:
            Validated Configuration object.

        Raises:
            UserException: If configuration is invalid.
        """
        try:
            config = Configuration(**self.configuration.parameters)
            logging.info(
                f"Configuration validated: {len(config.endpoints)} endpoints configured"
            )
            return config
        except Exception as e:
            raise UserException(f"Configuration error: {str(e)}")

    def _load_previous_state(self) -> dict[str, Any]:
        """
        Load state from previous run.

        Returns:
            State dictionary from previous run.
        """
        state = self.get_state_file()
        logging.info(f"Loaded previous state: {state}")
        return state

    def _extract_endpoint(
        self,
        client: AcumaticaClient,
        endpoint_config: EndpointConfig,
        incremental: bool,
        page_size: int,
    ) -> None:
        """
        Extract data from a single Acumatica endpoint.

        Args:
            client: Authenticated Acumatica client.
            endpoint_config: Configuration for the endpoint to extract.
            incremental: Whether to use incremental output.
            page_size: Number of records to fetch per API request.
        """
        logging.info(f"Extracting endpoint: {endpoint_config.endpoint}")

        entities = client.get_entities(
            endpoint=endpoint_config.endpoint,
            version=endpoint_config.version,
            expand=endpoint_config.expand,
            filter_expr=endpoint_config.filter,
            select=endpoint_config.select,
            top=page_size,
        )

        records_written = self._write_entities_to_table(
            entities, endpoint_config.output_table, incremental
        )

        logging.info(
            f"Extracted {records_written} records from {endpoint_config.endpoint}"
        )

    def _write_entities_to_table(
        self, entities: Iterator[dict[str, Any]], table_name: str, incremental: bool
    ) -> int:
        """
        Write entities to output table as CSV.

        Flattens nested structures and handles various data types.

        Args:
            entities: Iterator of entity dictionaries from API.
            table_name: Name of the output table.
            incremental: Whether to use incremental mode.

        Returns:
            Number of records written.
        """
        output_table_path = self._get_output_table_path(table_name)

        # Collect all records and determine all columns
        flattened_records = []
        all_columns: set[str] = set()

        for entity in entities:
            flattened = self._flatten_entity(entity)
            flattened_records.append(flattened)
            all_columns.update(flattened.keys())

        records_written = len(flattened_records)
        csv_columns = sorted(all_columns)  # Sort for consistent column order

        if records_written > 0:
            with open(
                output_table_path, mode="w", encoding="utf-8", newline=""
            ) as out_file:
                writer = csv.DictWriter(out_file, fieldnames=csv_columns)
                writer.writeheader()

                for record in flattened_records:
                    writer.writerow(record)

            self._create_table_manifest(table_name, csv_columns, incremental)

        return records_written

    def _get_output_table_path(self, table_name: str) -> Path:
        """
        Get the full path for output table file.

        Args:
            table_name: Name of the output table.

        Returns:
            Path to the output CSV file.
        """
        tables_out_path = Path(self.tables_out_path)
        return tables_out_path / f"{table_name}.csv"

    def _create_table_manifest(
        self, table_name: str, columns: list[str], incremental: bool
    ) -> None:
        """
        Create table manifest for output table.

        Args:
            table_name: Name of the output table.
            columns: List of column names.
            incremental: Whether to use incremental mode.
        """
        table = self.create_out_table_definition(
            name=f"{table_name}.csv", incremental=incremental, primary_key=[]
        )
        self.write_manifest(table)
        logging.debug(f"Created manifest for table: {table_name}")

    @staticmethod
    def _flatten_entity(
        entity: dict[str, Any], parent_key: str = "", sep: str = "_"
    ) -> dict[str, Any]:
        """
        Flatten nested dictionary structure.

        Converts nested dictionaries to flat structure with concatenated keys.
        Example: {'a': {'b': 1}} becomes {'a_b': 1}

        Args:
            entity: Entity dictionary to flatten.
            parent_key: Parent key for nested structures.
            sep: Separator for concatenating keys.

        Returns:
            Flattened dictionary.
        """
        items: list[tuple[str, Any]] = []

        for key, value in entity.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key

            if isinstance(value, dict) and value:
                # Recursively flatten nested dictionaries
                items.extend(Component._flatten_entity(value, new_key, sep).items())
            elif isinstance(value, list):
                # Convert lists to JSON-like string representation
                items.append((new_key, str(value)))
            else:
                # Keep primitive values as-is
                items.append((new_key, value))

        return dict(items)

    def _update_state(self, state: dict[str, Any]) -> None:
        """
        Update state file with new information.

        Args:
            state: State dictionary to persist.
        """
        from datetime import datetime

        state["last_run_timestamp"] = datetime.now().isoformat()
        self.write_state_file(state)
        logging.debug("State file updated")


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
