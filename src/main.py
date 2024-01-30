import argparse
from jsonschema import validate
import json
import csv
import os
import xml.etree.ElementTree as ET 
from graphviz import Digraph
import requests
from requests.exceptions import ConnectionError

def convert_sbom_to_csv(sbom_json_path, csv_output_path):
    """
    Convert SBOM JSON data to a CSV file.

    Args:
        sbom_json_path (str): Path to the SBOM JSON file.
        csv_output_path (str): Path where the CSV output will be saved.
    """
    # Load the SBOM JSON data
    with open(sbom_json_path, 'r') as file:
        sbom_data = json.load(file)

    # Extract components
    components = sbom_data.get('components', [])

    # Open CSV file for writing
    with open(csv_output_path, mode='w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['name', 'version', 'type', 'description', 'licenses']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Write the header
        writer.writeheader()

        # Write data for each component
        for component in components:
            # Extract license information if available
            licenses = [lic['license']['id'] for lic in component.get('licenses', [])]
            license_str = ', '.join(licenses)

            # Write the component data
            writer.writerow({
                'name': component.get('name', ''),
                'version': component.get('version', ''),
                'type': component.get('type', ''),
                'description': component.get('description', ''),
                'licenses': license_str
            })

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
    # with open(schema_file, 'r') as file:
    #    schema = json.load(file)
    # validate(instance=sbom, schema=schema)
    pass

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
    if sbom_format == 'cyclonedx':
        dependencies = process_cyclonedx_sbom(sbom)
    elif sbom_format == 'spdx':
        # Process SPDX format
        dependencies = process_spdx_sbom(sbom)
    else:
        dependencies = []
    
    return dependencies

def process_spdx_sbom(sbom):
    """
    Process SPDX SBOM in JSON format
    Args:
        sbom (dict): Parsed SBOM data
    Returns:
        list of dict: Processed dependencies.
    """
    dependencies = []

    # SPDX SBOMs have a 'packages' section listing all components
    if 'packages' in sbom:
        for package in sbom['packages']:
            dep_info = {
                'name': package.get('name', 'Unknown'),
                'version': package.get('versionInfo', 'Unknown'),
                'supplier': package.get('supplier', 'Unknown'),
                'downloadLocation': package.get('downloadLocation', 'Unknown'),
                'filesAnalyzed': package.get('filesAnalyzed', False),
                'licenseConcluded': package.get('licenseConcluded', 'Unknown'),
                'licenseDeclared': package.get('licenseDeclared', 'Unknown'),
                # Add more fields as necessary
            }
            dependencies.append(dep_info)

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
    dot = Digraph(comment='Dependency Tree', format='pdf')
    dot.attr(rankdir='LR', dpi='300')  # High resolution for clarity

    # Define a dictionary to hold subgraph clusters
    clusters = {}

    # Iterate through the components and their dependencies
    for component in sbom:
        if 'name' in component:
            component_name = component['name']
            component_version = component.get('version', 'Unknown')
            component_cluster = component.get('cluster', 'default')  # Assume there is a 'cluster' key

            # If the cluster does not exist, create it
            if component_cluster not in clusters:
                clusters[component_cluster] = Digraph(name=f'cluster_{component_cluster}')
                clusters[component_cluster].attr(label=component_cluster, color='lightgrey')

            # Create a label for the node with the name and version
            component_label = f"{component_name}\n{component_version}"

            # Add the node to the appropriate cluster
            clusters[component_cluster].node(component_name, label=component_label)

            # Add edges for dependencies within the same cluster
            if 'dependencies' in component:
                for dependency in component['dependencies']:
                    if 'name' in dependency:
                        dependency_name = dependency['name']
                        dependency_version = dependency.get('version', 'Unknown')
                        edge_label = f"Version: {dependency_version}"
                        clusters[component_cluster].edge(component_name, dependency_name, label=edge_label)

    # Add all clusters to the main graph
    for cluster in clusters.values():
        dot.subgraph(cluster)

    # Remove global node attributes that override individual settings
    dot.node_attr.clear()

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
    parser = argparse.ArgumentParser(description='SBOMVisor is up and running!')
    parser.add_argument('file', help='Path to SBOM file')
    parser.add_argument('format', help='Format of SBOM (e.g., cyclonedx, spdx)',
                        choices=['cyclonedx', 'spdx'])
    args = parser.parse_args()

    schema_file_cyclonedx = "schema_cyclonedx.json"
    schema_file_spdx = "schema_spdx.json"

    # URL for CycloneDX and SPDX schemas
    schema_urls = {
        'cyclonedx':"https://cyclonedx.org/schema/bom-1.5.schema.json",
        'spdx': "https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json"
    }

    # Determine which schema to download based on the format
    schema_url = schema_urls[args.format]
    schema_file = schema_file_cyclonedx if args.format == 'cyclonedx' else schema_file_spdx

    # Check if the schema file already exists
    if not os.path.exists(schema_file):
        download_result = download_schema(schema_url, schema_file)

        if not os.path.exists(schema_file):
            print(f"Failed to download schema: {download_result}")
        return
    else:
        print(f"Schema file '{schema_file}' already exists. Skipping download.")

    sbom = parse_sbom(args.file, args.format)
    
    if sbom is not None:
        # Pass both sbom and the format to process_sbom
        dependencies = process_sbom(sbom, args.format)
        if dependencies:
            tree = generate_dependency_tree(dependencies)
            tree.render('dependency_tree.gv', view=True)    # Saves and closes the dependency tree

            # Generate and save the CSV file
            csv_output_path = 'sbom_data.csv'
            convert_sbom_to_csv(args.file, csv_output_path)
            print(f"CSV file saved as {csv_output_path}")

            vulnerabilites = check_all_vulnerabilites(dependencies)
            print("Vulnerabilities Report:", vulnerabilites)
        else:
            print("No dependencies found.")
    else:
        print("Failed to parse SBOM")

if __name__ == "__main__":
    main()