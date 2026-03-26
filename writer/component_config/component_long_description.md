# Acumatica Writer

Writes data from Keboola Storage tables into Acumatica ERP via the Acumatica REST API.

## How it works

Each configured table maps a Keboola input CSV to an Acumatica entity endpoint. Records are upserted using the Acumatica REST API PUT operation — existing records are updated, new records are created, identified by their natural key fields.

## Authentication

Uses the same OAuth 2.0 or username/password authentication as the extractor.

## Field format

CSV column values are sent as plain strings. Acumatica's API accepts these and converts them to the appropriate field types automatically.
