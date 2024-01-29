import argparse
from jsonschema import validate
import json
import os
import xml.etree.ElementTree as ET 
from graphviz import Digraph
import requests
from requests.exceptions import ConnectionError

def download_schema(url, file_name):

    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open(file_name, 'w') as file:
                file.write(response.text)
            return file_name
        else:
            return f"Error: Unable to download the schema. HTTP status code: {response.status_code}"
    except Exception as e:
        return f"Error: {e}"

def process_cyclonedx_sbom(sbom):
    """
    Process CycloneDX SBOM in JSON format
    Args:
        sbom (dict): Parsed SBOM data
    Returns:
        list of dict: Processed dependencies.
    """
    dependencies = []

    if 'components' in sbom:
        for comp in sbom['components']:
            dep_info = {
                'type': comp.get('type', 'Unknown'),
                'name': comp.get('name', 'Unknown'),
                'version': comp.get('version', 'Unknown'),
                'group': comp.get('group', ''),
                'purl': comp.get('purl', ''),
                'dependencies': [],
                'pedigree': [],
                'evidence': []
            }

            # Process dependencies if available
            if 'components' in comp:
                for sub_comp in comp['components']:
                    dep_info['dependencies'].append({
                        'type': sub_comp.get('type', 'Unknown'),
                        'name': sub_comp.get('name', 'Unknown'),
                        'version': sub_comp.get('version', 'Unknown')
                    })

            # Process pedigree if available
            if 'pedigree' in comp:
                for ancestor in comp['pedigree'].get('ancestors', []):
                    dep_info['pedigree'].append({
                        'type': ancestor.get('type', 'Unknown'),
                        'name': ancestor.get('type', 'Unknown'),
                        'version': ancestor.get('version', 'Unknown'),
                        'purl': ancestor.get('purl', '')
                    })

            # Process occurrences if available
            if 'evidence' in comp and 'occurrences' in comp['evidence']:
                for occurrence in comp['evidence']['occurrences']:
                    dep_info['evidence'].append({
                        'bom-ref': occurrence.get('bom-ref', ''),
                        'location': occurrence.get('location', '')
                    })
            dependencies.append(dep_info)
    
    # Process global dependencies section if available
    if 'dependencies' in sbom:
        for dep in sbom['dependencies']:
            ref = dep.get('ref', '')
            depends_on = dep.get('dependsOn', [])
            # Find the corresponding component and add its dependencies
            for d in dependencies:
                if d.get('name') == ref or d.get('purl') == ref:
                    d['dependencies'].extend(depends_on)

    return dependencies

def validate_sbom(sbom, schema_file):

    """
    Validate SBOM agaisnt its JSON Schema.
    Args:
        sbom (dict): SBOM data in dictionary format.
        schema_file (str): Path to the JSON Schema file.
    """
    with open(schema_file, 'r') as file:
        schema = json.load(file)
    validate(instance=sbom, schema=schema)

def process_sbom(sbom, sbom_format):
    """
    Updated function to handle different SBOM formats.
    Args:
        sbom (dict): SBOM data.
        sbom_format (str): Format of the SBOM, e.g., 'cyclonedx', 'spdx'.
    Returns: 
        list of dict: Processed dependencies.

    Process the SBOM data to extract necessary information for dependency tree and vulnerability checks.
    This implementation assumes a certain structure of the SBOM. You may need to modify it based on your SBOM format.
    """
    dependencies = []

    if sbom_format == 'cyclonedx':
        # Process CycloneDX format
        # ...
        dependencies = process_cyclonedx_sbom(sbom)

    elif sbom_format == 'spdx':
        # Process SPDX format
        # ...
    
        return dependencies

def get_file_type(file_path):
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
    """
    Generate a dependency tree graph using Graphviz.
    Args:
        sbom (list of dict): The structured representation of the components and their dependencies.
    Returns:
        Digraph: The Graphviz Digraph representing the dependency tree.
    """
    dot = Digraph(comment='Dependency Tree')

    # Iterate through the components and their dependencies
    for component in sbom:
        # Check if 'name' key exists
        if 'name' in component:
            component_name = component['name']
            component_version = component.get('version', 'Unknown')

            # Add the component node with its name and version as label
            dot.node(component_name, label=f"{component_name}\nVersion: {component_version}")

            # Add edges for dependencies
            if 'dependencies' in component:
                for dependency in component['dependencies']:
                    if 'name' in dependency:  # Ensure dependency also has 'name'
                        dependency_name = dependency['name']
                        dot.edge(component_name, dependency_name)
        else:
            # Handle components without a name, e.g., log a warning
            pass

    return dot

def check_all_vulnerabilites(dependencies):
    vulnerabilities_report = {}
    for dep in dependencies:
        vulnerabilities = check_vulnerabilities(dep['name'])
        vulnerabilities_report[dep['name']] = vulnerabilities
    return vulnerabilities_report

def check_vulnerabilities(library):
    # Make a request to vulnerability database
    try:
        response = requests.get(f'https://vuldb.com/api/{library}')
        if response.status_code == 200:
            # Process the response and extract relevant information
            # Fornow, just returning the staus code for simplicity
            return response.status_code
    except requests.RequestException as e:
        # Handle exceptions related to the request
        print(f"Error while checking vulnerabilities for {library}: {e}")
        return {}

def parse_sbom(file_path, sbom_format):
    file_type = get_file_type(file_path)
    if file_type == '.json':
        with open(file_path, 'r') as file:
            sbom = json.load(file)
            validate_sbom(sbom, f'schema_{sbom_format}.json') # Assuming you have a corresponding schema file
            return sbom
    elif file_type == '.xml':
        return parse_sbom_xml(file_path)
    else:
        print("Unsupported file type")
        return None

def main():
    # Download the CycloneDX JSON schema
    schema_url = "https://cyclonedx.org/schema/bom-1.5.schema.json"
    schema_file = "schema_cyclonedx.json"
    download_result = download_schema(schema_url, schema_file)

    if not os.path.exists(schema_file):
        print(f"Failed to download schema: {download_result}")
        return

    parser = argparse.ArgumentParser(description='SBOMVisor is up and running!')
    parser.add_argument('file', help='Path to SBOM file')
    parser.add_argument('format', help='Format of SBOM (e.g., cyclonedx, spdx)',
                        choices=['cyclonedx', 'spdx'])
    args = parser.parse_args()

    sbom = parse_sbom(args.file, args.format)
    
    if sbom:
        # Pass both sbom and the format to process_sbom
        dependencies = process_sbom(sbom, args.format)
        tree = generate_dependency_tree(dependencies)
        tree.render('dependency_tree.gv', view=True)    # Saves and closes the dependency tree

        vulnerabilites = check_all_vulnerabilites(dependencies)
        print("Vulnerabilities Report:", vulnerabilites)

if __name__ == "__main__":
    main()