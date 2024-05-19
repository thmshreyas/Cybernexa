import requests
import json
# Define the Vulners API endpoint and the data payload
url = 'https://vulners.com/api/v3/search/lucene/'
software_list = ["Apache", "Nginx", "WordPress", "PHP", "MySQL", "Drupal"]  # Add more software names as needed

api_key = "API_KEY"  # Replace with your actual API key

for software in software_list:
    data = {
        "query": software,
        "apiKey": api_key
    }

    try:
        # Make the POST request to the Vulners API
        response = requests.post(url, json=data)
        response.raise_for_status()  # Raises an HTTPError for bad responses

        # Parse the JSON response
        response_data = response.json()

        # Check if the response contains data
        if 'data' in response_data and 'search' in response_data['data']:
            print(f"Results for {software}:")
            # Iterate over each item in the 'search' array
            for item in response_data['data']['search']:
                # Extract relevant information from the item
                cve_id = item.get('_id')
                cvss_score = item.get('_source')['cvss']['score']
                description = item.get('_source')['description']
                published_date = item.get('_source')['published']
                last_modified_date = item.get('_source')['modified']

                # Print the extracted information
                print("CVE ID:", cve_id)
                print("CVSS Score:", cvss_score)
                print("Description:", description)
                print("Published Date:", published_date)
                print("Last Modified Date:", last_modified_date)
                print("------------------------")
        else:
            print(f"No data found for {software}.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred for {software}: {e}")
    except ValueError as e:
        print(f"JSON decode error for {software}: {e}")
