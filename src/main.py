import argparse
import json
import os
import xml.etree.ElementTree as ET 
from graphviz import Digraph
import requests

def process_sbom(sbom):
    # Extract data necessary for dependency tree and vulnerability check
    # This will depend on the structure of your SBOM
    # e.g., list of dependencies, versions, etc
    pass

def get_file_type(file_path)
    _, file_extension = os.path.splitext(file_path)
    return file_extension.lower()

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
    for dep in dependencies:
        dot.node(dep['name'], dep['name'])
        if 'dependencies' in dep:
            for child in dep['dependencies']:
                dot.edge(dep['name'], child['name'])
    # Add nodes and edges based on SBOM Structure
    # dot.node('A', 'Library A')
    # dog.edge('A', 'B')
    return dot

def check_all_vulnerabilites(dependencies):
    vulnerabilities_report = {}
    for dep in dependencies:
        vulnerabilities = check_vulnerabilities(dep['name'])
        vulnerabilities_report[dep['name']] = vulnerabilities
    return vulnerabilities_report

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
    file_type = get_file_type(args.file)
    if file_type == '.json':
        sbom = parse_sbom_json(args.file)
    elif file_type == '.xml':
        sbom = parse_sbom_xml(args.file)
    else:
        print("Unsupported file type")
        return
    # Generate dependency tree and check for vulnerabilities
    # Output results
    sbom = None
    if file_type == '.json':
        sbom = parse_sbom_json(args.file)
    elif file_type == '.xml':
        sbom = parse_sbom_xml(args.file)

    if sbom:
        dependencies = process_sbom(sbom)
        tree = generate_dependency_tree(dependencies)
        tree.render('dependency_tree.gv', view=True)    # Saves and closes the dependency tree

        vulnerabilites = check_all_vulnerabilites(dependencies)
        print("Vulnerabilities Report:", vulnerabilites)

if __name__ == "__main__":
    main()