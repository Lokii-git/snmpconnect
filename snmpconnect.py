#!/usr/bin/env python3

from pysnmp.hlapi import *
import argparse
import logging
import time
from tqdm import tqdm
import configparser
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import re

# Configure logging
logging.basicConfig(filename='snmp_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def display_banner():
    version = 'v1.2.0'
    creator = '@lokii-git'
    banner = f"""
 :::===  :::= === :::=======  :::====      :::===== :::====  :::= === :::= === :::===== :::===== :::====
 :::     :::===== ::: === === :::  ===     :::      :::  === :::===== :::===== :::      :::      :::====
  =====  ======== === === === =======      ===      ===  === ======== ======== ======   ===        ===  
     === === ==== ===     === ===          ===      ===  === === ==== === ==== ===      ===        ===   {creator}
 ======  ===  === ===     === ===           =======  ======  ===  === ===  === ========  =======   ===   {version}
                                                                                                         
    SNMP Penetration Testing Script
    ===================================
    This script performs SNMP queries and walks on a list of IP addresses.
    It can operate in two modes:
    1. **Interactive Mode**: Prompts the user for SNMP community string, OIDs, and other settings.
    2. **Non-Interactive Mode**: Reads configuration and IP list from provided files.

    Usage:
    python snmpconnect.py <iplist> <config> [--ip IP] [--interactive] [--verbose]

    - `<iplist>`: Path to the file containing a list of IP addresses for scanning (default: iplist.txt).
    - `<config>`: Path to the configuration file containing SNMP settings (default: config.ini).
    - `--ip IP`: Optional. Single IP address to test instead of using the IP list.
    - `--interactive`: Optional. Run in interactive mode to manually input settings.
    - `--verbose`: Optional. Enable detailed output for debugging and progress tracking.

    Example:
    python snmpconnect.py iplist.txt config.ini
    python snmpconnect.py iplist.txt config.ini --ip 192.168.1.1
    python snmpconnect.py iplist.txt config.ini --interactive
    python snmpconnect.py iplist.txt config.ini --verbose
    """
    print(banner)




def sanitize_ip(ip):
    """Remove unwanted characters and handle different formats."""
    ip = ip.strip().lower()
    if ip.startswith('http://'):
        ip = ip[7:]
    return ip

def snmp_query(target, community, oid, retries, results, delay=1, snmp_version=2):
    max_delay = 60  # Maximum delay time in seconds
    current_delay = delay
    for attempt in range(retries):
        try:
            if snmp_version == 3:
                iterator = nextCmd(
                    SnmpEngine(),
                    UsmUserData('user', 'authKey1', 'privKey1', authProtocol=usmHMACMD5, privProtocol=usmDES),
                    UdpTransportTarget((target, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False
                )
            else:
                iterator = nextCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=snmp_version - 1),  # SNMP v1 or v2c
                    UdpTransportTarget((target, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False
                )

            for (errorIndication, errorStatus, errorIndex, varBinds) in iterator:
                if errorIndication:
                    logging.error(f'Error: {errorIndication} (Target: {target})')
                    print(f'Error: {errorIndication} (Target: {target})')
                    return
                elif errorStatus:
                    logging.error(f'SNMP Error: {errorStatus.prettyPrint()} (Target: {target})')
                    print(f'SNMP Error: {errorStatus.prettyPrint()} (Target: {target})')
                    return
                else:
                    for varBind in varBinds:
                        result = (target, oid, str(varBind[1]))
                        results.append(result)
                        logging.info(f'{result}')
                        print(f'{result}')
            break  # Exit loop if successful

        except Exception as e:
            logging.error(f'Attempt {attempt + 1} failed: {e}')
            print(f'Attempt {attempt + 1} failed: {e}')
            if attempt < retries - 1:
                time.sleep(current_delay)
                current_delay = min(current_delay * 2, max_delay)  # Exponential backoff
            else:
                logging.error(f'Failed after {retries} attempts.')
                print(f'Failed after {retries} attempts.')

def snmp_walk(target, community, oid, retries, results, delay=1, snmp_version=2):
    max_delay = 60  # Maximum delay time in seconds
    current_delay = delay
    for attempt in range(retries):
        try:
            if snmp_version == 3:
                iterator = bulkCmd(
                    SnmpEngine(),
                    UsmUserData('user', 'authKey1', 'privKey1', authProtocol=usmHMACMD5, privProtocol=usmDES),
                    UdpTransportTarget((target, 161)),
                    ContextData(),
                    0, 25,  # Non-repeaters, Max-repetitions
                    ObjectType(ObjectIdentity(oid))
                )
            else:
                iterator = bulkCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=snmp_version - 1),  # SNMP v1 or v2c
                    UdpTransportTarget((target, 161)),
                    ContextData(),
                    0, 25,  # Non-repeaters, Max-repetitions
                    ObjectType(ObjectIdentity(oid))
                )

            for (errorIndication, errorStatus, errorIndex, varBinds) in iterator:
                if errorIndication:
                    logging.error(f'Error: {errorIndication} (Target: {target})')
                    print(f'Error: {errorIndication} (Target: {target})')
                    return
                elif errorStatus:
                    logging.error(f'SNMP Error: {errorStatus.prettyPrint()} (Target: {target})')
                    print(f'SNMP Error: {errorStatus.prettyPrint()} (Target: {target})')
                    return
                else:
                    for varBind in varBinds:
                        result = (target, oid, str(varBind[1]))
                        results.append(result)
                        logging.info(f'{result}')
                        print(f'{result}')
            break  # Exit loop if successful

        except Exception as e:
            logging.error(f'Attempt {attempt + 1} failed: {e}')
            print(f'Attempt {attempt + 1} failed: {e}')
            if attempt < retries - 1:
                time.sleep(current_delay)
                current_delay = min(current_delay * 2, max_delay)  # Exponential backoff
            else:
                logging.error(f'Failed after {retries} attempts.')
                print(f'Failed after {retries} attempts.')

def process_ip_list(file_path, community, oids, retries, results, delay=1, single_ip=None, snmp_version=2):
    ip_list = []
    if single_ip:
        ip_list = [sanitize_ip(single_ip)]
        print(f'Using single IP address: {single_ip}')
    else:
        try:
            with open(file_path, 'r') as file:
                content = file.read().strip()
                if not content:
                    print(f'Warning: {file_path} is empty or only contains whitespace.')
                    print(f'Please provide a valid IP list or use the interactive mode.')
                    return

                # Handle different formats of IP lists
                lines = content.splitlines()
                for line in lines:
                    ips = re.split(r'\s|,', line)  # Split by whitespace or comma
                    for ip in ips:
                        sanitized_ip = sanitize_ip(ip)
                        if sanitized_ip:
                            ip_list.append(sanitized_ip)

            if not ip_list:
                print(f'Warning: No valid IP addresses found in {file_path}.')
                print(f'Please check the file format or provide IPs directly.')
                return

            print(f'Loaded IP addresses from {file_path}')

        except FileNotFoundError:
            print(f'Error: File {file_path} not found.')
            return

    total_tasks = len(ip_list) * len(oids)
    print(f'Starting SNMP scan for {len(ip_list)} IPs and {len(oids)} OIDs. Total tasks: {total_tasks}')

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for ip in ip_list:
            for oid in oids:
                futures.append(executor.submit(snmp_query, ip, community, oid, retries, results, delay, snmp_version))
        
        # Progress bar
        for _ in tqdm(as_completed(futures), total=total_tasks, desc="Processing"):
            pass

    export_results(results)

def export_results(results, file_path='snmp_results.csv'):
    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Target', 'OID', 'Value'])
        for result in results:
            writer.writerow(result)
    print(f'Results exported to {file_path}')

def interactive_mode():
    community = input('Enter SNMP community string: ')
    oids = input('Enter OIDs (comma-separated): ').split(',')
    retries = int(input('Enter number of retries: '))
    iplist = input('Enter path to IP file: ')
    delay = int(input('Enter delay between requests (seconds): '))
    snmp_version = int(input('Enter SNMP version (1, 2, or 3): '))

    process_ip_list(iplist, community, oids, retries, [], delay=delay, snmp_version=snmp_version)

def main():
    display_banner()

    parser = argparse.ArgumentParser(description='SNMP Penetration Testing Script')
    parser.add_argument('iplist', nargs='?', default='iplist.txt', help='Path to file containing list of IP addresses')
    parser.add_argument('config', nargs='?', default='config.ini', help='Path to configuration file')
    parser.add_argument('--ip', help='Single IP address to test instead of using the IP list')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--verbose', action='store_true', help='Enable detailed output')
    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
    else:
        config = configparser.ConfigParser()
        config.read(args.config)

        community = config.get('SNMP', 'community')
        oids = config.get('SNMP', 'oids').split(',')
        retries = config.getint('SNMP', 'retries')
        delay = int(config.get('SNMP', 'delay', fallback=1))
        snmp_version = config.getint('SNMP', 'version', fallback=2)

        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            print('Verbose mode enabled')

        process_ip_list(args.iplist, community, oids, retries, [], delay=delay, single_ip=args.ip, snmp_version=snmp_version)

if __name__ == '__main__':
    main()
