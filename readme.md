# SNMPConnect

**Version:** 1.2.0  
**Creator:** @lokii-git
![2024-08-21 14_29_46-kali-linux-2024 2-virtualbox-amd64  Running  - Oracle VM VirtualBox](https://github.com/user-attachments/assets/d7132786-85d0-4f8c-b5d2-3c71dc107abb)

## Overview

**SNMPConnect** is a Python-based script designed for penetration testing SNMP (Simple Network Management Protocol) services across various devices. It supports all versions of SNMP (v1, v2c, and v3) and provides robust features for automated scanning, detailed logging, and interactive user inputs. This tool is ideal for security professionals and enthusiasts looking to assess and secure network infrastructures.

## Features

- **SNMP Version Support**: Works with SNMPv1, SNMPv2c, and SNMPv3.
- **Automated IP Handling**: Automatically uses IP addresses from `iplist.txt` unless a specific IP is provided.
- **Interactive Mode**: Allows users to input SNMP community strings, OIDs, and other settings directly.
- **Concurrent Scanning**: Utilizes threading for faster scanning across multiple IPs.
- **Detailed Logging**: Logs all activities, errors, and results to `snmp_scan.log`.
- **Results Export**: Exports SNMP query results to `snmp_results.csv`.
- **User Feedback**: Verbose mode provides detailed feedback on script progress and actions.
- **Flexible IP Input**: Supports various IP formats, including single IP, comma-separated IPs, or IPs with HTTP headers.

## Installation

### Prerequisites

Ensure Python 3 is installed. The following Python packages are required:
- `pysnmp`
- `argparse`
- `logging`
- `tqdm`
- `configparser`
- `concurrent.futures`
- `csv`

Install these packages using pip:

```sh
pip install pysnmp tqdm
