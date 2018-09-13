import boto3
import requests
import re
import logging
import os
from multiprocessing import Process


# Logging Information
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s:%(name)s:%(levelname)s:%(message)s')
file_handler = logging.FileHandler('LOG-tor-blacklist.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Create AWS Session
region = os.getenv('AWS_DEFAULT_REGION', default='us-east-1')
client = boto3.client('waf-regional', region_name=region)


# Crawl Tor's website and add IPs to a list
def add_ips_to_list(tor_ips):
    tor_ips = []
    # URL for Tor Exit Nodes and RegEx Pattern for IP
    url_tor = "https://check.torproject.org/exit-addresses"
    tor_pattern = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    # Read URL content
    r = requests.get(url_tor)

    # Add TOR IPs to the list
    for line in r.iter_lines():
        if line:
            tor_search = re.search(tor_pattern, line.decode('utf-8'))
            if tor_search:
                tor_ips.append((tor_search.group(1) + "/32"))

    # Remove duplicates
    tor_ips = set(tor_ips)
    return tor_ips


# # Get Change Token to modify WAF objects
def get_change_token():
    token = client.get_change_token()
    # return token['ChangeToken']
    return token['ChangeToken']


# Add IPs to IP Set
def update_ip_set(ip_set_id, ip):
    # Updates IP Set
    client.update_ip_set(
        IPSetId=ip_set_id,
        ChangeToken=get_change_token(),
        Updates=[{
            'Action': 'INSERT',
            'IPSetDescriptor': {
                'Type': 'IPV4',
                'Value': ip
            }
        }]
    )


def main(mp=True):
    # Get Change Token
    change_token = get_change_token()

    # Create list of IPs
    tor_ips = []
    tor_ips = add_ips_to_list(tor_ips)

    # # Create IP Set
    ip_set_name = 'TOR-NODES'
    ip_set = client.create_ip_set(
        Name=ip_set_name,
        ChangeToken=change_token
    )

    # Return the IPSetId
    ip_set_id = ip_set['IPSet']['IPSetId']
    # Run with Multiprocess
    if mp:
        # Create list for processes and connections
        processes = []

        # Create a process per IP
        for ip in tor_ips:
            # Create the process andcat pass instance and connection
            process = Process(target=update_ip_set, args=(ip_set_id, ip))
            processes.append(process)

        # Start all processes
        for process in processes:
            process.start()

        # Make sure that all processes have finished
        for process in processes:
            process.join()
    # Run single process
    else:
        for ip in tor_ips:
            update_ip_set(ip_set_id, ip)


main(mp=False)
# main()
