import argparse
import json
import random
from datetime import datetime, timedelta, timezone

def random_future_time(min_days: int = 7, max_days: int = 30) -> str:
    """Return a timestamp in the exact format 2026-10-28T13:21:55.00000Z."""
    delta_days = random.randint(min_days, max_days)
    future_dt = datetime.now(timezone.utc) + timedelta(days=delta_days)

    # Build the string manually to guarantee the required format
    return (
        f"{future_dt.year:04d}-"
        f"{future_dt.month:02d}-"
        f"{future_dt.day:02d}T"
        f"{future_dt.hour:02d}:"
        f"{future_dt.minute:02d}:"
        f"{future_dt.second:02d}."
        f"{future_dt.microsecond:05d}Z"
    )

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Modify expirationTime in a JSON file: replace null values with a random future timestamp.'
    )
    parser.add_argument('filename', help='Path to the JSON file to modify')
    args = parser.parse_args()

    # Load the JSON file
    with open(args.filename, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Navigate to the value list: data['pages'][0]['value']
    try:
        if 'pages' not in data or not isinstance(data['pages'], list) or len(data['pages']) == 0:
            print('Invalid JSON structure: missing "pages" list or it is empty.')
            return
        
        first_page = data['pages'][0]
        if 'value' not in first_page or not isinstance(first_page['value'], list):
            print('Invalid JSON structure: missing "value" list in the first page.')
            return
        
        value_list = first_page['value']
    except (KeyError, IndexError, TypeError) as e:
        print(f'Error accessing JSON structure: {e}')
        return

    # Process each entry
    for entry in value_list:
        # Check if expirationTime is null (None in Python)
        if entry.get('expirationTime') is None:
            continue  # Skip null entries

        # Generate a new timestamp between 7 and 30 days in the future
        new_timestamp = random_future_time()
        entry['expirationTime'] = new_timestamp

    # Write the modified JSON back to the file
    with open(args.filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

if __name__ == '__main__':
    main()
