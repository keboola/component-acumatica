# Acumatica Extractor

A Keboola component for extracting data from Acumatica ERP system via its REST API.

**Table of Contents:**

- [Acumatica Extractor](#acumatica-extractor)
  - [Description](#description)
  - [Prerequisites](#prerequisites)
  - [Features](#features)
  - [Supported Endpoints](#supported-endpoints)
  - [Configuration](#configuration)
    - [Authentication](#authentication)
      - [Setting Up OAuth Authentication](#setting-up-oauth-authentication)
    - [Connection Settings](#connection-settings)
      - [Acumatica URL](#acumatica-url)
      - [Page Size](#page-size)
    - [Endpoint Configuration](#endpoint-configuration)
      - [Tenant / Version](#tenant--version)
      - [Endpoint Name](#endpoint-name)
      - [Expand (Optional)](#expand-optional)
      - [Filter (Optional)](#filter-optional)
      - [Select (Optional)](#select-optional)
    - [Additional Options](#additional-options)
      - [Override Global Page Size](#override-global-page-size)
      - [Page Size for Current Endpoint](#page-size-for-current-endpoint)
    - [Destination](#destination)
      - [Load Type](#load-type)
      - [Primary Keys](#primary-keys)
  - [Example Configuration](#example-configuration)
  - [Output](#output)
    - [Data Flattening](#data-flattening)
  - [Development](#development)
    - [Project Structure](#project-structure)
  - [Integration](#integration)
  - [Troubleshooting](#troubleshooting)
    - [Common Issues](#common-issues)
      - [OAuth Authorization Failed](#oauth-authorization-failed)
      - [Token Refresh Issues](#token-refresh-issues)
      - [Endpoint Not Found](#endpoint-not-found)
      - [No Data Returned](#no-data-returned)
      - [Rate Limiting](#rate-limiting)
  - [Alternative Authentication](#alternative-authentication)
  - [License](#license)

## Description

This extractor component connects to Acumatica ERP systems and extracts data from configured endpoints. It supports:

- Multiple endpoint extraction in a single run
- OData query parameters (expand, filter, select)
- Automatic pagination for large datasets
- Nested data flattening
- OAuth 2.0 authentication with automatic token refresh
- Incremental loading support

## Prerequisites

Before using this component, ensure you have:

1. **Access to an Acumatica instance** with REST API enabled
2. **OAuth Setup** - Please contact Keboola support to enable OAuth authentication for your Acumatica instance. This is a one-time setup required for your organization.
3. **Acumatica OAuth Application** - Your Acumatica instance must have an OAuth application configured (under Integration → Connected Applications) with the Authorization Code flow enabled
4. **API version information** (typically in format like "25.200.001")
5. **Knowledge of endpoints** you want to extract (e.g., Customer, SalesOrder, Invoice)

## Features

| **Feature**             | **Description**                                          |
|-------------------------|----------------------------------------------------------|
| OAuth 2.0 Authentication | Secure OAuth 2.0 with automatic token refresh          |
| Generic Configuration   | Flexible configuration for multiple endpoints            |
| OData Support          | Full support for $expand, $filter, and $select           |
| Auto Pagination        | Handles pagination automatically for large datasets      |
| Data Flattening        | Automatically flattens nested JSON structures to CSV     |
| Incremental Loading    | Optional incremental mode for output tables              |
| State Management       | Persistent OAuth tokens across runs                      |
| Retry Logic            | Built-in retry mechanism for failed API requests         |

## Supported Endpoints

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

## Configuration

### Authentication

This component uses **OAuth 2.0** for secure authentication with Acumatica.

#### Setting Up OAuth Authentication

1. **Contact Keboola Support** - Request to enable OAuth authentication for your Acumatica instance (one-time setup)
2. **Authorize the Component** - In the Keboola UI, click "Authorize" to connect your Acumatica account
3. **Complete Authorization** - Log in to your Acumatica instance and grant permissions
4. **Done!** - The component will automatically manage authentication and token refresh from this point forward

The OAuth tokens are securely stored and automatically refreshed during data extraction runs.

### Connection Settings

#### Acumatica URL

Full URL to your Acumatica instance (e.g., `https://your-instance.acumatica.com` or `http://your-server/AcumaticaERP`).

#### Page Size

Number of records to fetch per API request (default: 2500). This is a global setting that applies to all configured endpoints.

### Endpoint Configuration

Configure one or more endpoints to extract. For each endpoint, specify:

#### Tenant / Version

Acumatica tenant and API version in format: `tenant/version` (e.g., `Default/25.200.001`). You can find available tenants and versions using the "Load Tenants & Versions" sync action.

#### Endpoint Name

The Acumatica entity endpoint name (e.g., `Customer`, `SalesOrder`, `Invoice`). Use the "Load Endpoints" sync action to see available endpoints for your selected tenant/version.

#### Expand (Optional)

Related entities to expand in the response. For example:
- `MainContact` - Expands the main contact details
- `Details` - Expands line item details
- Multiple expansions: `MainContact,BillingAddress`

#### Filter (Optional)

OData filter expression to filter records. Examples:
- `CustomerID eq 'C001'`
- `OrderDate gt '2024-01-01'`
- `Status eq 'Active'`

#### Select (Optional)

OData select expression to retrieve specific fields only. Examples:
- `CustomerID,CustomerName,Status`
- Reduces payload size when you only need specific columns

### Additional Options

#### Override Global Page Size

Enable to use a custom page size for this specific endpoint instead of the global page size setting.

#### Page Size for Current Endpoint

Number of records to fetch per API request for this specific endpoint. Only visible when "Override Global Page Size" is enabled.

### Destination

Configure output table settings for all endpoints:

#### Load Type

Choose between:
- **Full Load**: The destination tables will be overwritten with each run
- **Incremental Load**: Data will be upserted into the destination tables. Tables with a primary key will have rows updated, tables without a primary key will have rows appended.

#### Primary Keys

Select primary key columns for each endpoint (configured per endpoint). Use the "Get Columns" button to load available columns from the endpoint schema. Required for incremental loads.

## Example Configuration

```json
{
  "acumatica_url": "https://your-instance.acumatica.com",
  "page_size": 2500,
  "debug": false,
  "endpoints": [
    {
      "enabled": true,
      "tenant_version": "Default/25.200.001",
      "endpoint": "Customer",
      "expand": "MainContact",
      "filter_expr": "Status eq 'Active'",
      "select": "",
      "primary_keys": ["CustomerID"]
    },
    {
      "enabled": true,
      "tenant_version": "Default/25.200.001",
      "endpoint": "SalesOrder",
      "expand": "Details",
      "filter_expr": "OrderDate gt '2024-01-01'",
      "select": "",
      "primary_keys": ["OrderNbr"]
    }
  ],
  "destination": {
    "load_type": "incremental_load"
  }
}
```

## Output

The component creates one CSV table for each configured endpoint:

- **Table Names**: Named after the endpoint (e.g., `Customer.csv`, `SalesOrder.csv`)
- **Columns**: Automatically detected from the first record
- **Nested Data**: Flattened with underscore notation (e.g., `MainContact_Email`)
- **Lists**: Converted to string representation
- **Manifest**: Automatically created for each output table
- **Load Mode**: Determined by `destination.load_type` (full_load or incremental_load)

### Data Flattening

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

## Development

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

### Project Structure

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

## Integration

For details about deployment and integration with Keboola, refer to the [deployment section of the developer documentation](https://developers.keboola.com/extend/component/deployment/).

## Troubleshooting

### Common Issues

#### OAuth Authorization Failed

- Verify your Acumatica URL is correct and accessible
- Ensure the OAuth application is properly configured in Acumatica (Integration → Connected Applications)
- Check that the OAuth broker is configured for your organization - please contact Keboola support if needed
- Verify the client ID and secret are correct in the OAuth application settings

#### Token Refresh Issues

- The component automatically refreshes OAuth tokens when they expire
- If you encounter persistent authentication errors, try re-authorizing the component
- OAuth tokens are securely stored in the component state and persist across runs

#### Endpoint Not Found

- Verify the tenant/version matches your Acumatica instance
- Check the endpoint name spelling (case-sensitive)
- Use the "Load Endpoints" button to see available endpoints

#### No Data Returned

- Check your filter expression syntax (OData format)
- Verify data exists matching your filter criteria
- Ensure the endpoint is enabled in the configuration

#### Rate Limiting

- The component includes automatic retry logic with exponential backoff
- Please contact your Acumatica administrator if rate limits are too restrictive

## Alternative Authentication

While OAuth 2.0 is the recommended authentication method, the component also supports username/password authentication for special cases. This method is hidden in the UI and requires manual configuration using the field names `acumatica_username` and `#acumatica_password`. If you need any assistance with this kind of setup, please contact Keboola support.

## License

MIT License - See LICENSE.md for details.
