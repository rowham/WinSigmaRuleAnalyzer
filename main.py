import os
import csv
from pathlib import Path
import subprocess
import re
import yaml
import json
from datetime import datetime

# Clone the Sigma repository
repo_url = "https://github.com/Neo23x0/sigma.git"
repo_path = "sigma"
if not os.path.exists(repo_path):
    subprocess.run(["git", "clone", repo_url, repo_path])

# Read eventIds.json and channel.json mapping files
mapping_file_path = "mapping data/eventIds.json"
channel_file_path = "mapping data/channel.json"
with open(mapping_file_path, "r") as mapping_file, open(channel_file_path, "r") as channel_file:
    event_ids_mapping = json.load(mapping_file)
    channel_mapping = json.load(channel_file)

# To Parse sigma rules
def parse_sigma_rule(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    try:
        sigma_data = yaml.safe_load(content)
        detection = sigma_data.get('detection', {})
    except yaml.YAMLError as e:
        print(f"Error loading YAML in file {file_path}: {e}")
        return None, None, []

    category = None
    service = None
    category_match = re.search(r'logsource:(.*?category:(.*?)(\n|$))', content, re.DOTALL)
    service_match = re.search(r'logsource:(.*?service:(.*?)(\n|$))', content, re.DOTALL)
    level_match = re.search(r'level:\s+(\w+)', content, re.IGNORECASE)

    level = level_match.group(1).strip() if level_match else "N/A"

    if category_match:
        rule_type = "Category"
        category = category_match.group(2).strip()

    elif service_match:
        rule_type = "Service"
        service = service_match.group(2).strip()
    else:
        rule_type = "N/A"
        category = None
        service = None

    event_ids = get_event_ids_from_detection(detection, category)

    return rule_type, category, service, event_ids, level

def get_event_ids_from_detection(detection, category):
    event_ids = set()
    if isinstance(detection, dict):
        for key, value in detection.items():
            if key == "EventID":
                if isinstance(value, list):
                    event_ids.update(map(str, value))
                else:
                    event_ids.add(str(value))
            elif isinstance(value, (dict, list)):
                event_ids.update(get_event_ids_from_detection(value, category))
    elif isinstance(detection, list):
        for item in detection:
            event_ids.update(get_event_ids_from_detection(item, category))

    mapped_ids = event_ids_mapping.get(category, [])

    if isinstance(mapped_ids, int):
        event_ids.add(str(mapped_ids))
    else:
        event_ids.update(map(str, mapped_ids))

    return event_ids

# To process all Sigma rule files in a directory
def process_sigma_directory(directory):
    results = {}

    for file_path in Path(directory).rglob("*.yml"):
        rule_type, category, service, event_ids, level = parse_sigma_rule(file_path)
        rule_key = category or service

        if not rule_key:
            rule_key = service
            print(f"Warning! One file has no service or category: {file_path}")

        if rule_key not in results:
            results[rule_key] = {"Type": rule_type, "Event IDs": set(), "File Count": 0}

        results[rule_key]["Event IDs"].update(event_ids)
        results[rule_key]["File Count"] += 1

        if level and level.lower() != 'n/a':
            level_key = level.capitalize()
            results[rule_key][level_key] = results[rule_key].get(level_key, 0) + 1
        else:
            print(f"Warning! Unexpected level value: {level} in file: {file_path}")

    return results

# Process Sigma rules in the specified directory
sigma_directory = "sigma/rules/windows/"
results = process_sigma_directory(sigma_directory)

# Write results to a CSV file
os.makedirs('output', exist_ok=True)
current_time = datetime.now().strftime("%Y%m%d%H%M%S")
save_path = f"./output/sigma_results_{current_time}.csv"

with open(save_path, "w", newline="") as csvfile:
    fieldnames = ["Type", "Service or Category", "Channel / Provider", "Event IDs", "Informational", "Low", "Medium", "High", "Critical", "Total Rules in Service or Category"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for rule_key, value in results.items():
        # Get "Channel / Provider" based on the "service or Category"
        channel_provider = channel_mapping.get(rule_key, "")

        writer.writerow({
            "Type": value["Type"],
            "Service or Category": rule_key,
            "Channel / Provider": channel_provider,
            "Event IDs": ", ".join(map(str, value["Event IDs"])),
            "Informational": value.get("Informational", 0),
            "Low": value.get("Low", 0),
            "Medium": value.get("Medium", 0),
            "High": value.get("High", 0),
            "Critical": value.get("Critical", 0),
            "Total Rules in Service or Category": value["File Count"]
        })

print(f"Results written to {save_path}")
