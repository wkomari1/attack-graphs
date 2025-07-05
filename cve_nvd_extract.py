

import requests
import pandas as pd
from datetime import datetime

# Define the directory and file name
output_dir = '/Users/thesis_cve_nvd'
output_file = f'{output_dir}/automotive_network_cves.xlsx'

# NVD API endpoint for fetching CVEs
nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# List of keywords to search for individually   
keyword_list = ['automotive', 'OBD', 'ECU', 'electronic network','telematics'] #when testing it seems there are NVD restrictions to the number of keywords to extract data to 5 keywords and also total limit of data fetch per page results to 2000
# Initialize an empty DataFrame to store the combined results
combined_df = pd.DataFrame()

for keyword in keyword_list:
    # Query parameters for the NVD API with the current keyword
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': 2000,  # can be adjusted
        'startIndex': 0
    }

    try:
        # Make the request to the NVD API
        response = requests.get(nvd_api_url, params=params)
        
        # Check if the response was successful
        if response.status_code == 200:
            try:
                data = response.json()
                
                # Check if 'vulnerabilities' key is present in the response
                if 'vulnerabilities' in data:
                    # Extract CVE information
                    cve_items = data['vulnerabilities']

                    # Prepare a list to hold the CVE information for this keyword
                    cve_list = []

                    for item in cve_items:
                        cve_id = item['cve']['id']
                        published_date_raw = item['cve'].get('published', None)
                        description = item['cve']['descriptions'][0]['value']

                        # Convert to lowercase for case-insensitive matching
                        description_lower = description.lower()

                        # Parse the published date correctly using pd.to_datetime
                        if published_date_raw:
                            try:
                                # Correct date parsing
                                published_date = pd.to_datetime(published_date_raw, format='%Y-%m-%dT%H:%M:%S.%f', errors='coerce')
                            except ValueError as e:
                                print(f"Error parsing date for CVE ID {cve_id}: {e}")
                                # In case of parsing error, set to None or an alternative format
                                published_date = None
                        else:
                            published_date = None

                        cve_list.append({
                            'CVE ID': cve_id,
                            'Published Date': published_date,
                            'Description': description  
                        })

                    # Convert the list to a DataFrame
                    cve_df = pd.DataFrame(cve_list)

                    # Ensure 'Published Date' is a column before converting
                    if 'Published Date' in cve_df.columns:
                        # Convert 'Published Date' to datetime (in case it wasn't converted earlier)
                        cve_df['Published Date'] = pd.to_datetime(cve_df['Published Date'], errors='coerce')

                        # Format the 'Published Date' to 'YYYY-MM-DD HH:MM:SS'
                        cve_df['Published Date'] = cve_df['Published Date'].dt.strftime('%Y-%m-%d %H:%M:%S')

                    # Append the current DataFrame to the combined DataFrame
                    combined_df = pd.concat([combined_df, cve_df], ignore_index=True)

                    print(f"Extracted {len(cve_list)} CVEs for keyword '{keyword}'")
                else:
                    print(f"No 'vulnerabilities' key found in the API response for keyword '{keyword}'.")
            except ValueError as e:
                print(f"Error parsing JSON for keyword '{keyword}': {e}")
        else:
            print(f"Failed to retrieve CVEs for keyword '{keyword}'. Status code: {response.status_code}")
            print(f"Response content: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed for keyword '{keyword}': {e}")

# Save the combined DataFrame to an Excel file
if not combined_df.empty:
    # Drop duplicated columns if any
    combined_df = combined_df.loc[:, ~combined_df.columns.duplicated()]
    
    # Save the DataFrame to an Excel file
    combined_df.to_excel(output_file, index=False)
    print(f"Combined CVEs saved to {output_file}")
else:
    print("No CVEs were extracted from any keyword search.")









