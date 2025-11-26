Acumatica Extractor
===================

A Keboola component for extracting data from Acumatica ERP system via its REST API.

**Table of Contents:**

- [Acumatica Extractor](#acumatica-extractor)
- [Description](#description)
- [Prerequisites](#prerequisites)
- [Features](#features)
- [Supported Endpoints](#supported-endpoints)
- [Configuration](#configuration)
  - [Connection Settings](#connection-settings)
    - [Acumatica URL](#acumatica-url)
    - [Username](#username)
    - [Password](#password)
    - [Company](#company)
  - [Endpoint Configuration](#endpoint-configuration)
    - [Endpoint Name](#endpoint-name)
    - [API Version](#api-version)
    - [Output Table Name](#output-table-name)
    - [Expand (Optional)](#expand-optional)
    - [Filter (Optional)](#filter-optional)
    - [Select (Optional)](#select-optional)
  - [Additional Options](#additional-options)
    - [Incremental Output](#incremental-output)
    - [Debug Mode](#debug-mode)
- [Example Configuration](#example-configuration)
- [Output](#output)
  - [Data Flattening](#data-flattening)
- [Development](#development)
  - [Project Structure](#project-structure)
- [Integration](#integration)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
    - [Authentication Failed](#authentication-failed)
    - [Endpoint Not Found](#endpoint-not-found)
    - [No Data Returned](#no-data-returned)
    - [Rate Limiting](#rate-limiting)
  - [Debug Mode](#debug-mode-1)
- [License](#license)

Description
===========

This extractor component connects to Acumatica ERP systems and extracts data from configured endpoints. It supports:

- Multiple endpoint extraction in a single run
- OData query parameters (expand, filter, select)
- Automatic pagination for large datasets
- Nested data flattening
- Session-based authentication
- Incremental loading support

Prerequisites
=============

Before using this component, ensure you have:

1. Access to an Acumatica instance with REST API enabled
2. Valid Acumatica credentials (username and password)
3. Company name configured in your Acumatica instance
4. API version information (typically in format like "23.200.001")
5. Knowledge of the entity endpoints you want to extract (e.g., Customer, SalesOrder, Invoice)

Features
========

| **Feature**             | **Description**                                          |
|-------------------------|----------------------------------------------------------|
| Generic Configuration   | Flexible configuration for multiple endpoints            |
| Session Authentication  | Secure session-based authentication with Acumatica       |
| OData Support          | Full support for $expand, $filter, and $select           |
| Auto Pagination        | Handles pagination automatically for large datasets      |
| Data Flattening        | Automatically flattens nested JSON structures to CSV     |
| Incremental Loading    | Optional incremental mode for output tables              |
| Retry Logic            | Built-in retry mechanism for failed API requests         |
| Debug Mode             | Detailed logging for troubleshooting                     |

Supported Endpoints
===================

This component supports all Acumatica REST API endpoints available in your instance. Common endpoints include:

- **Customer** - Customer master data
- **SalesOrder** - Sales orders with details
- **Invoice** - Invoice documents
- **Payment** - Payment information
- **Vendor** - Vendor master data
- **PurchaseOrder** - Purchase orders
- **Item** - Inventory items
- **Employee** - Employee records
- **JournalTransaction** - Journal entries
- **FinancialPeriod** - Financial periods

The component automatically adapts to any endpoint structure. If you need help configuring specific endpoints, please submit your request to [ideas.keboola.com](https://ideas.keboola.com/).

Configuration
=============

Connection Settings
-------------------

### Acumatica URL
Full URL to your Acumatica instance (e.g., `https://your-instance.acumatica.com`).

### Username
Your Acumatica login username. This field is encrypted in storage.

### Password
Your Acumatica login password. This field is encrypted in storage.

### Company
The company name configured in your Acumatica instance to connect to.

Endpoint Configuration
----------------------

Configure one or more endpoints to extract. For each endpoint, specify:

### Endpoint Name
The Acumatica entity endpoint name (e.g., `Customer`, `SalesOrder`, `Invoice`).

### API Version
The API version to use (e.g., `23.200.001`). You can find this in your Acumatica API documentation.

### Output Table Name
The name for the output table in Keboola Storage (e.g., `customers`, `sales_orders`).

### Expand (Optional)
Related entities to expand in the response. For example:
- `MainContact` - Expands the main contact details
- `Details` - Expands line item details
- Multiple expansions: `MainContact,BillingAddress`

### Filter (Optional)
OData filter expression to filter records. Examples:
- `CustomerID eq 'C001'`
- `OrderDate gt '2024-01-01'`
- `Status eq 'Active'`

### Select (Optional)
OData select expression to retrieve specific fields only. Examples:
- `CustomerID,CustomerName,Status`
- Reduces payload size when you only need specific columns

Additional Options
------------------

### Incremental Output
Enable incremental loading mode for output tables. When enabled, data is appended rather than replaced.

### Debug Mode
Enable detailed debug logging for troubleshooting. Useful when configuring new endpoints or investigating issues.

Example Configuration
=====================

```json
{
  "acumatica_url": "https://your-instance.acumatica.com",
  "#acumatica_username": "admin",
  "#acumatica_password": "your-password",
  "company": "MyCompany",
  "endpoints": [
    {
      "endpoint": "Customer",
      "version": "23.200.001",
      "output_table": "customers",
      "expand": "MainContact",
      "filter": "Status eq 'Active'",
      "select": ""
    },
    {
      "endpoint": "SalesOrder",
      "version": "23.200.001",
      "output_table": "sales_orders",
      "expand": "Details",
      "filter": "OrderDate gt '2024-01-01'",
      "select": ""
    }
  ],
  "incremental_output": false,
  "debug": false
}
```

Output
======

The component creates one CSV table for each configured endpoint:

- **Table Names**: As specified in the `output_table` configuration
- **Columns**: Automatically detected from the first record
- **Nested Data**: Flattened with underscore notation (e.g., `MainContact_Email`)
- **Lists**: Converted to string representation
- **Manifest**: Automatically created for each output table

Data Flattening
---------------

Nested JSON structures are automatically flattened:

**Input:**
```json
{
  "CustomerID": "C001",
  "CustomerName": "ACME Corp",
  "MainContact": {
    "Email": "contact@acme.com",
    "Phone": "555-1234"
  }
}
```

**Output CSV:**
```
CustomerID,CustomerName,MainContact_Email,MainContact_Phone
C001,ACME Corp,contact@acme.com,555-1234
```

Development
===========

To customize the local data folder path, replace the `CUSTOM_FOLDER` placeholder with your desired path in the `docker-compose.yml` file:

```yaml
volumes:
  - ./:/code
  - ./CUSTOM_FOLDER:/data
```

Clone this repository and run the component using:

```bash
git clone <repository-url> component-acumatica-extractor
cd component-acumatica-extractor
uv sync
uv run python src/component.py
```

Run tests:

```bash
uv run python -m unittest tests.test_component -v
```

Code formatting and linting:

```bash
uv run ruff format src/ tests/
uv run ruff check --fix src/ tests/
```

Docker development:

```bash
docker-compose build
docker-compose run --rm dev
```

Project Structure
-----------------

```
component-acumatica-extractor/
├── src/
│   ├── component.py           # Main component logic
│   ├── acumatica_client.py    # Acumatica API client
│   └── configuration.py       # Configuration classes
├── tests/
│   └── test_component.py      # Unit tests
├── component_config/
│   └── configSchema.json      # Configuration schema
├── data/
│   ├── config.json           # Sample configuration
│   └── in/
│       └── state.json        # State file
└── README.md
```

Integration
===========

For details about deployment and integration with Keboola, refer to the [deployment section of the developer documentation](https://developers.keboola.com/extend/component/deployment/).

Troubleshooting
===============

Common Issues
-------------

### Authentication Failed
- Verify your Acumatica URL, username, password, and company name
- Ensure your user has API access permissions in Acumatica
- Check if the Acumatica instance REST API is enabled

### Endpoint Not Found
- Verify the API version matches your Acumatica instance
- Check the endpoint name spelling (case-sensitive)
- Consult your Acumatica REST API documentation

### No Data Returned
- Check your filter expression syntax
- Verify data exists matching your filter criteria
- Enable debug mode to see detailed API requests

### Rate Limiting
- The component includes automatic retry logic
- Contact your Acumatica administrator if rate limits are too restrictive

Debug Mode
----------

Enable debug mode in the configuration to see:
- Detailed API request/response information
- Authentication flow details
- Pagination progress
- Data transformation steps

License
=======

MIT License - See LICENSE.md for details.
