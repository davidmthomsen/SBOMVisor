import argparse
import json
import xml.etree.ElementTree as ET 
from graphviz import Digraph
import requests

def parse_sbom_json(file_path):
    with open(file_path, 'r') as file:
        sbom = json.load(file)
        # process the SBOM
        return sbom
    
def parse_sbom_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    # process the SBOM
    return root

def generate_dependency_tree(sbom):
    dot = Digraph(comment='Dependency Tree')
    # Add nodes and edges based on SBOM Structure
    # dot.node('A', 'Library A')
    # dog.edge('A', 'B')
    return dot

def check_vulnerabilities(library):
    # Make a request to vulnerability database
    response = requests.get(f'https://vulndb.com/api/{library}')
    if response.status_code == 200:
        vulnerabilities = response.json()
        return vulnerabilities
    return {}

def main():
    parser = argparse.ArgumentParser(description='SBOMVisor is up and running!')
    parser.add_argument('file', help='Path to SBOM file')
    args = parser.parse_args()

    # Depending on file type, call parse_sbom_json or parse_sbom_xml
    # Generate dependency tree and check for vulnerabilities
    # Output results

if __name__ == "__main__":
    main()