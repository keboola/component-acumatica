This Keboola extractor component connects to Acumatica ERP systems and extracts data from endpoints set up as configuration rows via the REST API.

Key features:
- Extract from any Acumatica REST API endpoint (Customer, SalesOrder, Invoice, etc.)
- Full OData support ($expand, $filter, $select)
- Automatic pagination for large datasets
- Session-based authentication with automatic cookie management
- Nested JSON to flat CSV conversion
- Configurable API versions
- Incremental loading support
- Built-in retry logic for reliability

The component handles all authentication, pagination, and data transformation automatically, delivering clean CSV tables ready for analysis in Keboola Storage.