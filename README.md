# SBOMVisor

SBOMVisor is a tool for converting Software Bill of Materials (SBOM) data to CSV format and generating dependency trees and vulnerability reports.

## Usage

```bash
python3 src/main.py <path_to_sbom_file> <sbom_format>
<path_to_sbom_file>: Path to the SBOM file in JSON or XML format.
<sbom_format>: Format of SBOM (e.g., cyclonedx, spdx).
```

## Installation
1. Clone the repository:
```bash
git clone https://github.com/davidmthomsen/SBOMVisor.git
cd SBOMVisor
```
2. Install dependencies:
```bash
pip3 install -r requirements.txt
```
3. Run the script:
```bash
python3 src/main.py <path_to_sbom_file> <sbom_format>
```

## Dependencies
* Pandas
* Graphviz
* CycloneDX-BOM
* Requests
* Jsonschema