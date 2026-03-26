"""
Acumatica Extractor Component.

Extracts data from Acumatica ERP system via REST API and saves to Keboola tables.
"""

import csv
import logging
import sys
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from extractor_configuration import Configuration, EndpointConfig
from keboola.component.exceptions import UserException
from keboola.vcr.sanitizers import IPv4UrlSanitizer
from shared.acumatica_base import AcumaticaSyncActionsMixin

VCR_SANITIZERS = [IPv4UrlSanitizer()]


class Component(AcumaticaSyncActionsMixin):
    config: Configuration  # narrows mixin's AcumaticaConnectionConfig
    """
    Acumatica Extractor Component.

    Extracts data from configured Acumatica endpoint and writes result to output table.
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
        """Main execution - orchestrates the component workflow."""
        try:
            logging.info("Starting Acumatica data extraction")

            if not self.config.endpoints:
                raise UserException("No endpoints configured. Please add at least one endpoint to extract.")

            self.client.authenticate()

            try:
                enabled_endpoints = [ep for ep in self.config.endpoints if ep.enabled]
                if not enabled_endpoints:
                    logging.warning("No enabled endpoints configured. Skipping extraction.")
                    return

                for idx, endpoint_config in enumerate(enabled_endpoints, 1):
                    logging.info(f"Processing endpoint {idx}/{len(enabled_endpoints)}: {endpoint_config.endpoint}")
                    self._extract_endpoint(endpoint_config)

                self._update_state()
                logging.info(
                    f"Acumatica data extraction completed successfully ({len(self.config.endpoints)} endpoints)"
                )
            finally:
                # Logout only for username/password auth to free up API user slot
                # OAuth doesn't need logout
                if self.client.acumatica_username and not self.client.oauth_access_token:
                    self.client.logout()

        except UserException:
            raise
        except Exception as e:
            error_msg = str(e)

            # Check for API login limit in the error message
            if "too many 500 error responses" in error_msg and "auth/login" in error_msg:
                raise UserException(
                    "API Login Limit reached. The Acumatica instance has too many active API sessions. "
                    "Please wait for existing sessions to expire or contact your Acumatica administrator "
                    "to increase the API user limit or manually log out active API users."
                )

            logging.exception("Unhandled error during extraction")
            raise UserException(f"Extraction failed: {error_msg}")

    def _extract_endpoint(self, endpoint_config: "EndpointConfig") -> None:
        """Extract data from a single Acumatica endpoint."""
        logging.info(f"Extracting endpoint: {endpoint_config.endpoint}")

        entities = self.client.get_entities(
            tenant_version=endpoint_config.tenant_version,
            endpoint=endpoint_config.endpoint,
            expand=endpoint_config.expand,
            filter_expr=endpoint_config.filter_expr,
            select=endpoint_config.select,
            top=self.config.page_size,
        )

        output_table_name = f"{endpoint_config.endpoint}.csv"
        incremental = self.config.destination.load_type == "incremental_load"
        primary_keys = endpoint_config.primary_keys
        records_written = self._write_entities_to_table(entities, output_table_name, incremental, primary_keys)

        logging.info(f"Extracted {records_written} records from {endpoint_config.endpoint}")

    def _write_entities_to_table(
        self, entities: Iterator[dict[str, Any]], table_name: str, incremental: bool, primary_keys: list[str]
    ) -> int:
        """
        Write entities to output table as CSV.

        Flattens nested structures and handles various data types.

        Args:
            entities: Iterator of entity dictionaries from API.
            table_name: Name of the output table.
            incremental: Whether to use incremental mode.
            primary_keys: List of primary key columns.

        Returns:
            Number of records written.
        """
        flattened_records = []
        all_columns: set[str] = set()

        for entity in entities:
            flattened = self._flatten_entity(entity)
            flattened_records.append(flattened)
            all_columns.update(flattened.keys())

        records_written = len(flattened_records)
        csv_columns = sorted(all_columns)

        if records_written > 0:
            table = self.create_out_table_definition(name=table_name, incremental=incremental, primary_key=primary_keys)
            logging.info(f"Table full_path: {table.full_path}")
            logging.info(f"Writing {records_written} records to {table.full_path}")

            with open(table.full_path, mode="w", encoding="utf-8", newline="") as out_file:
                writer = csv.DictWriter(out_file, fieldnames=csv_columns)
                writer.writeheader()
                for record in flattened_records:
                    writer.writerow(record)

            logging.info("File written, now writing manifest")
            self.write_manifest(table)
            logging.info(f"Manifest written for table: {table_name}")

        return records_written

    @staticmethod
    def _flatten_entity(entity: dict[str, Any], parent_key: str = "", sep: str = "_") -> dict[str, Any]:
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
            elif isinstance(value, dict):
                # Skip empty dicts — nothing to flatten, no value to emit
                pass
            elif isinstance(value, list):
                # Convert lists to JSON-like string representation
                items.append((new_key, str(value)))
            else:
                # Keep primitive values as-is
                items.append((new_key, value))

        return dict(items)

    def _update_state(self) -> None:
        """Update local state file with last run timestamp."""
        if self._state is None:
            self._state = {}

        self._state["last_run_timestamp"] = datetime.now().isoformat()

        logging.info("Writing last_run_timestamp to local state file")
        self.write_state_file(self._state)
        logging.debug("Local state file updated")


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
