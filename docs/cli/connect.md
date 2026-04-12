# connect.py - SMC Connection Module

## Overview

The `connect.py` module handles authentication and session management for the Forcepoint SMC (Security Management Center) API.

## Functions

### `load_config(config_path=None)`

Loads SMC configuration from `config.ini`.

**Parameters:**
- `config_path` (optional): Path to config file. Defaults to `config.ini` in the same directory.

**Returns:** Dictionary with connection parameters.

### `connect(config_path=None)`

Establishes a session with the SMC server.

**Parameters:**
- `config_path` (optional): Path to config file.

**Returns:** `True` if connection successful.

**Prints:** Connection status, API version, and session ID.

### `disconnect()`

Closes the active SMC session.

## Configuration File

The module reads from `config.ini`:

```ini
[smc]
smc_address = smc.example.com    # SMC server hostname/IP
smc_port = 8082                   # API port (default: 8082)
smc_apikey = YOUR_API_KEY         # API authentication key
smc_ssl = True                    # Use HTTPS
verify_ssl = False                # Verify SSL certificate
domain = Your Domain              # Admin domain (optional)
```

## Usage

### As a Module

```python
from connect import connect, disconnect

# Connect to SMC
connect()

# ... perform operations ...

# Disconnect
disconnect()
```

### Standalone Test

```bash
python connect.py
```

This runs a connection test and prints the result.

## Getting an API Key

1. Log into SMC Web Interface
2. Navigate to: **Home → Others → API Clients**
3. Create a new API Client
4. Copy the generated **Authentication Key**
5. Paste it into `config.ini` as `smc_apikey`

## Error Handling

The module raises exceptions for:
- Missing configuration file
- Invalid credentials
- Network connectivity issues
- SSL certificate errors (if `verify_ssl=True`)

## Example Output

```
Connected to SMC at https://smc.example.com:8082
API Version: 6.10
Session ID: abc123...
```
