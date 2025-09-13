# StrongDM Resource Manager

A comprehensive GUI application for managing StrongDM resources including SSH, RDP, and Database connections. Supports both individual resource creation and bulk CSV import.

## Features

- **Authentication**: Secure API key authentication with StrongDM
- **Single Resource Creation**: Interactive forms for creating SSH, RDP, and database resources
- **Bulk CSV Import**: Import multiple resources from CSV files with validation
- **Dynamic Configuration**: Automatically loads available tags, secret stores, and proxy clusters from your tenant
- **Debug Tools**: Built-in testing and troubleshooting capabilities
- **Cross-Platform**: Works on Windows with plans for Mac support

## Supported Resource Types

### SSH Resources
- Username/password authentication
- Private key authentication
- Configurable ports and hostnames
- Tag and proxy cluster assignment

### RDP Resources
- Username/password authentication
- Resource lock configuration
- NLA connection downgrade options
- Tag and proxy cluster assignment

### Database Resources
- MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Oracle
- Database-specific configuration
- Connection string management
- Tag and proxy cluster assignment

## Installation

### Prerequisites
- Python 3.7 or higher
- StrongDM API credentials with appropriate permissions

### Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python strongdm_manager.py
   ```

## Usage

### Initial Setup
1. Launch the application
2. Enter your StrongDM API Access Key and Secret Key in the Login tab
3. Click "Connect" to authenticate

### Creating Single Resources
1. After authentication, navigate to the "Add Single Resource" tab
2. Select the resource type (SSH, RDP, or Database)
3. Fill in the required fields marked with *
4. Configure optional settings like tags, secret stores, and proxy clusters
5. Click "Create Resource"

### Bulk CSV Import
1. Navigate to the "CSV Bulk Import" tab
2. Use the example template (example_resources.csv) as a reference
3. Select your CSV file using the "Browse" button
4. Configure import options:
   - Skip errors: Continue processing even if some rows fail
   - Dry run: Validate the CSV without creating resources
5. Click "Import Resources"

### CSV Format
Required columns:
- `type`: SSH, RDP, MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Oracle
- `name`: Unique resource name
- `hostname`: Target hostname or IP
- `port`: Connection port
- `username`: Authentication username
- `password`: Password or private key content

Optional columns:
- `tags`: Resource tags
- `secret_store`: Secret store name or "None"
- `proxy_cluster`: Proxy cluster name or "None (use gateway)"
- `database_name`: Database name (for database resources)
- `key_type`: "password" or "private_key" (for SSH resources)
- `lock_required`: "true" or "false" (for RDP resources)
- `downgrade_nla`: "true" or "false" (for RDP resources)

### Debug Tab
Use the Debug tab to:
- Test API connectivity
- List existing resources
- Query resources with filters
- Troubleshoot authentication issues

## API Permissions Required

Your StrongDM API key must have the following permissions:
- Resources: Create, Read, List
- Tags: Read, List
- Secret Stores: Read, List
- Proxy Clusters: Read, List

## Security Notes

- API credentials are only stored in memory during the session
- Passwords and private keys are masked in the interface
- All API communications use StrongDM's secure authentication
- No credentials are logged or persisted to disk

## Troubleshooting

### Authentication Issues
- Verify your API credentials are correct
- Ensure your API key has sufficient permissions
- Check network connectivity to StrongDM services

### Resource Creation Failures
- Verify all required fields are completed
- Check that hostnames and ports are accessible
- Ensure resource names are unique
- Use the Debug tab to test connectivity

### CSV Import Issues
- Validate CSV format matches the required structure
- Check for special characters in resource names
- Use dry run mode to validate before importing
- Review error messages in the import results

## Building Executable

To create a standalone Windows executable:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed strongdm_manager.py
```

The executable will be created in the `dist/` directory.

## Support

For issues related to:
- StrongDM API: Consult the official StrongDM documentation
- Application bugs: Check logs in the Debug tab
- Feature requests: Review the StrongDM API capabilities

## License

This application is provided as-is for managing StrongDM resources. Ensure compliance with your organization's security policies when using API credentials.
