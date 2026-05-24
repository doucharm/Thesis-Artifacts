import json
import csv
from collections import Counter
from pathlib import Path

directory_path = Path('.') 
output_csv_path = 'vulnerability_metrics.csv'

# Define the exact severities we want as columns, in order of importance
expected_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
csv_rows = []

for file_path in directory_path.glob('*.json'):
    print(f"Processing {file_path.name}...")
    file_severities = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"  -> Skipping {file_path.name}: Not a valid JSON file.")
            continue
            
    # Extract severities
    for result in data.get('Results') or []:
        for vuln in result.get('Vulnerabilities') or []:
            severity = vuln.get('Severity')
            if severity:
                file_severities.append(severity.upper())
                
    # Count them up
    counts = Counter(file_severities)
    
    # Build a row dictionary for the CSV
    row_data = {'Service': file_path.name}
    for severity in expected_severities:
        # Use .get() to default to 0 if a file has none of that specific severity
        row_data[severity] = counts.get(severity, 0)
        
    csv_rows.append(row_data)

# Write everything to a CSV file
if csv_rows:
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        # Define the header order
        fieldnames = ['Service'] + expected_severities
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(csv_rows)
        
    print(f"\nSuccess! Exported {len(csv_rows)} records to '{output_csv_path}'.")
else:
    print("\nNo data found to export.")