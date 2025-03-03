# 4ID4 Platform Automation

A robust automation script for 4ID4 platform that supports multi-wallet operation with proxy support.

## Features

- Multi-wallet automation for AIDA platform
- Proxy support (one proxy per wallet)
- Error handling with retry mechanisms
- Automatic proxy verification and failover
- Supports multiple private key formats
- Detailed logging of operations

## Requirements

- Python 3.6+
- Required Python packages:
  - requests
  - web3
  - loguru
  - json
  - time
  - os
  - sys
  - datetime
  - glob
  - random

## Installation

1. Clone or download this repository
2. Install the required packages:
   ```
   pip install requests web3 loguru
   ```

## Configuration

### Private Keys Setup

You can set up your private keys in two ways:

1. A single `pk.txt` file with one private key per line:
   ```
   0x123abc...
   0x456def...
   ```

2. Multiple files named `pk_1.txt`, `pk_2.txt`, etc., each containing a single private key.

The script automatically removes the `0x` prefix if present.

### Proxy Setup

Create a file named `proxy.txt` with one proxy per line:

```
ip:port
username:password@ip:port
```

The script will automatically match each wallet with the corresponding proxy in the file. If you have more wallets than proxies, the remaining wallets will run without proxies.

## Usage

Run the script with:

```
python aida.py
```

The script will:
1. Authenticate each wallet
2. Join the configured campaign
3. Process available missions that are supported
4. Claim rewards
5. Provide detailed logs of operations

## Customization

### Supported Mission Types

You can customize which mission types are automatically processed by modifying the `SUPPORTED_MISSION_TYPES` list:

```python
SUPPORTED_MISSION_TYPES = [
    "MANUAL", 
    "CONNECT_TWITTER", 
    "CONNECT_WALLET",
    "LIKE_TWEET", 
    "JOIN_TELEGRAM",
    "CREATE_WALLET"
]
```

### Advanced Configuration

The script contains various configuration options that can be modified directly in the code to customize its behavior for different requirements.

## Logging

The script provides detailed logs both to the console and to a file (`aida.log`). 

The log file rotates when it reaches 5 MB to avoid consuming too much disk space.

## Error Handling

The script includes comprehensive error handling:
- Proxy validation and fallback
- Request retries with exponential backoff
- Detailed error reporting
- Mission-specific retry logic

## Notes

- "Invite" missions are automatically skipped
- The script uses a random delay between processing wallets to avoid detection
- Failed requests will be retried with increasing delays

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is meant for educational purposes only. Use at your own risk. Be aware that automation may violate the terms of service of some platforms.
