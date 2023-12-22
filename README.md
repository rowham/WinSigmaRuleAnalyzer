# Sigma Windows Rule Analyzer

This repository provides a simple script to parse [#Sigma](https://github.com/SigmaHQ/sigma) rules and map the event IDs to their corresponding channels or providers. The script downloads Sigma rules from sigma rule repository and produces a CSV file with the mapped event IDs, their corresponding channels or providers, and the rule type (category or service).


## Overview

The script performs the following tasks:

1. **Clone Sigma Repository:** If the Sigma repository doesn't exist locally, it is cloned from [https://github.com/Neo23x0/sigma.git](https://github.com/Neo23x0/sigma.git).

2. **Read Mapping Files:** Event IDs and channel mappings are loaded from `mapping data/eventIds.json` and `mapping data/channel.json`, respectively.

3. **Parse Sigma Rules:** Sigma rules are parsed to extract relevant information such as type, category, service, event IDs, and detection level.

4. **Process Sigma Directory:** All Sigma rule files in the specified directory (`sigma/rules/windows/`) are processed to generate statistics.

5. **Write Results to CSV:** The results are written to a CSV file in the `output` directory, including information such as rule type, service or category, channel/provider, event IDs, and rule counts based on severity levels.


## Usage

The script requires only Python and Git to be installed. Just clone the [WinSigmaRuleAnalyzer](https://github.com/rowham/WinSigmaRuleAnalyzer.git) repository and run the main.py file.

```
git clone https://github.com/rowham/WinSigmaRuleAnalyzer.git
python3 main.py
```

## Output

The script will produce a CSV file named `sigma_results_<timestamp>.csv` in the `output` directory. The CSV file will have the following columns:

- `Type`: The type of the rule (category or service)
- `Service or Category`: The service or category of the rule
  - Sigma rules contain either a service field OR a category. [Refer to the official Sigma Rule documentation (Rule-Creation-Guide#log-source)](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide#log-source). 
- `Channel / Provider`: The corresponding channel or provider for the event IDs
  -  This column has been enriched by the script, aiding in the identification of entries related to Sysmon or Powershell.
- `Event IDs`: A comma-separated list of event IDs
  - This column contains either EventIDs used in the rules or is enriched by the script. Though not perfect, it provides an overview. [Check the sigma log source configuration](https://github.com/SigmaHQ/sigma/tree/master/documentation/logsource-guides/windows).
- `Level`: This column displays the number of rules per 'Service or Category' at each level.
In theory, higher level triggers more critical alert.
For more information about levels in Sigma rules, [refer to the documentation (Rule-Creation-Guide#level)](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide#level).
  - `Informational`: The number of informational rules
  - `Low`: The number of low-priority rules
  - `Medium`: The number of medium-priority rules
  - `High`: The number of high-priority rules
  - `Critical`: The number of critical rules
- `Total Rules in Service or Category`: The total number of rules in the service or category
  - This column shows the quantity of rules per 'Service or Category'.
It would be beneficial to understand the number of Sigma rules that can be implemented for a given log source or a win channel.

The output CSV file will contain the mapped event IDs, their corresponding channels or providers, and the rule type (category or service) for all the Sigma rules in the `sigma/rules/windows` directory.

## Notes

- The script may output warnings for certain rule files with missing service or category information or unexpected level values.
- Feel free to customize this simple script or contribute to its development.

## License
**MIT License**

Licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
