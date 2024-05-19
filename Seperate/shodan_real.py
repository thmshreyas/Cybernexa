import shodan
import json
import requests

SHODAN_API_KEY = "APIKEY"
api = shodan.Shodan(SHODAN_API_KEY)

enter = input("Enter IP address: ")
url = f'https://api.shodan.io/shodan/host/{enter}?key={SHODAN_API_KEY}'
response = requests.get(url)

if response.status_code == 200:
    js = response.json()

    print(json.dumps(js, indent=4))  # Pretty print the whole JSON response

    # Parse and print specific details
    print("\nParsed Information:")
    print(f"IP: {js.get('ip_str', 'N/A')}")
    print(f"Organization: {js.get('org', 'N/A')}")
    print(f"Operating System: {js.get('os', 'N/A')}")
    print(f"ISP: {js.get('isp', 'N/A')}")
    print(f"Last Update: {js.get('last_update', 'N/A')}")

    # Check for and print vulnerabilities if they exist
    vulnerabilities = js.get('vulns', None)
    if vulnerabilities:
        print("\nVulnerabilities:")
        for vuln in vulnerabilities:
            print(f"- {vuln}")
            if 'cvss' in vulnerabilities[vuln]:
                print(f"  CVSS Score: {vulnerabilities[vuln]['cvss']}")
            if 'cve' in vulnerabilities[vuln]:
                print(f"  CVEs: {', '.join(vulnerabilities[vuln]['cve'])}")
    else:
        print("No vulnerabilities found.")

    # Print open ports and services
    ports = js.get('ports', [])
    if ports:
        print("\nOpen Ports:")
        for port in ports:
            print(f"- {port}")
    else:
        print("No open ports found.")

    # Extract detailed information from each service
    for service in js.get('data', []):
        print(f"\nService on port {service.get('port', 'N/A')}:")
        print(f"  Banner: {service.get('banner', 'N/A')}")
        print(f"  Transport: {service.get('transport', 'N/A')}")
        print(f"  Product: {service.get('product', 'N/A')}")
        print(f"  Version: {service.get('version', 'N/A')}")
        print(f"  CPE: {service.get('cpe', 'N/A')}")

        # Extract SSL/TLS information if available
        ssl_data = service.get('ssl', None)
        if ssl_data:
            print("\n  SSL/TLS Information:")
            for key, value in ssl_data.items():
                if isinstance(value, list):
                    value = ', '.join(value)
                print(f"    {key.capitalize()}: {value}")

        # Extract CVEs from service if available
        cves = service.get('cve', [])
        if cves:
            print("\n  CVEs:")
            for cve in cves:
                print(f"    - {cve}")

        # Extract other fields like http title, server, etc.
        if 'http' in service:
            print("\n  HTTP Information:")
            http_data = service['http']
            print(f"    Title: {http_data.get('title', 'N/A')}")
            print(f"    Server: {http_data.get('server', 'N/A')}")
else:
    print(f"Error: Unable to fetch data for IP {enter}. HTTP Status Code: {response.status_code}")
