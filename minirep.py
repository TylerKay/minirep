# This an interactive script that gathers information about an IP address from various services

import argparse
import colorama
import json
import os
import requests
from os.path import dirname
import socket

# Initialize IP lists
dropIPs, alertIPs, passIPs = [], [], []

def fetch_vt_reputation(address,config):

    headers = {'x-apikey': config['vt_api_key']}
    response = requests.get(url=f"{config['vt_api_url']}/ip_addresses/{address}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed VT IP address lookup for {address}. Status code: {response.status_code}. Message: {response.text}")
        return
        
def security_trails_lookup(address,config):
    # ---- Security Trails API ----
    # Set your API key and the domain you want to retrieve information for
    threat_trails_api_key = config['security_trails_api_key']
    DOMAIN = socket.gethostbyaddr(address)[0]

    # Set the API endpoint URL
    url = f'https://api.securitytrails.com/v1/domain/{DOMAIN}/subdomains'

    # Set the request headers with your API key
    headers = {'APIKEY': threat_trails_api_key}

    # Send a GET request to the API endpoint
    response = requests.get(url, headers=headers)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Retrieve the subdomains data from the API response
        subdomains_data = response.json()
        
        # Print the subdomains data
        print(f'Total subdomains found: {len(subdomains_data["subdomains"])}')
        print('Subdomains:')
        subdomains = []
        for subdomain in subdomains_data['subdomains']:
            subdomains.append(subdomain)
            print(subdomain)
        print("^^^^^ A couple of subdomains ^^^^^")

    else:
        # Print an error message if the request was not successful
        print('Error retrieving subdomains data.')
    

def ip_geolocation_lookup(address,config):
    API_KEY = config['ip_geolocation_api_key']
    IP_ADDRESS = address

    # Set the API endpoint URL
    url = f'https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={IP_ADDRESS}'

    # Send a GET request to the API endpoint
    response = requests.get(url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Retrieve the geolocation data from the API response
        geolocation_data = response.json()
        
        print('''----------------------------IP GEOLOCATION DATA ----------------------------''''')
        # Print the geolocation data
        print(f'IP Address: {geolocation_data["ip"]}')
        print(f'City: {geolocation_data["city"]}')
        # print(f'Region: {geolocation_data["region_name"]}')
        print(f'Country: {geolocation_data["country_name"]}')
        print(f'Latitude: {geolocation_data["latitude"]}')
        print(f'Longitude: {geolocation_data["longitude"]}')
        print(f'Timezone: {geolocation_data["time_zone"]}')
    else:
        # Print an error message if the request was not successful
        print('Error retrieving geolocation data.')

def options(ip_addr):
    print("After seeing all the information from three APIs, would you like to: ")
    print("1. DROP \n2. ALERT \n3. PASS") 
    option = input("Enter your option (1, 2, or 3): ")

    if option == "1":
        dropIPs.append(ip_addr)
        print(f"IP address {ip_addr} has been added to the DROP list")
    elif option == "2":
        alertIPs.append(ip_addr)
        print(f"IP address {ip_addr} has been added to the alert list")
    elif option == "3":
        passIPs.append(ip_addr)
        print(f"IP address {ip_addr} has been added to the pass list")
    else:
        return None


def main(args):

    colorama.init()

    # If no address was supplied, prompt
    if not args.Address:
        ip_addr = input("Enter the IP address you would like to check: ")
    else:
        ip_addr = args.Address

    # Load config. Print warning and exit if not found
    try:
        config_file_path = os.path.join(dirname(os.path.realpath(__file__)),"minirep.json")
        # config = json.load(open(config_file_path)) 
        config = json.load(open(config_file_path)) 

    except Exception as e:
        print(f"Failed to load config file from {config_file_path}.\r\nException: {e}")
        return

    # Print the directions. Comment this out when you no longer need it
    # render_directions()

    # Query VirusTotal for IP reputation. Feel free to discard this section or use it in a different way
    if vt_rep := fetch_vt_reputation(ip_addr,config):
        print(json.dumps(vt_rep, indent=4))
        # cprint(colored("""
        print("""----------------------------VIRUS TOTAL REPUTATION DATA ----------------------------""")
        print(f"Reputation Score: {vt_rep['data']['attributes']['reputation']}")
        print(f"Harmless Votes: {vt_rep['data']['attributes']['total_votes']['harmless']}")
        print(f"Malicious Votes: {vt_rep['data']['attributes']['total_votes']['malicious']}")


    # Add your code here
    # ---- IPGeolocation API ----
    ip_geolocation_lookup(ip_addr,config)

    # Security Trails API
    security_trails_lookup(ip_addr,config)

    # Ask user for options of if they want to DROP, ALERT, or PASS
    options(ip_addr)
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--Address", help ="IP address to scan")
    
    args = parser.parse_args()
    main(args)