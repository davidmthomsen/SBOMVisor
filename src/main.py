import argparse
import jsonschema
import json
import csv
import os
import pandas as pd
import xml.etree.ElementTree as ET 
from graphviz import Digraph
import requests
from requests.exceptions import ConnectionError

def convert_sbom_to_csv(sbom_data, csv_output_path):
    """Convert SBOM data to a CSV file.

    Args:
        sbom_data (dict): The SBOM data in dictionary format.
        csv_output_path (str): The path where the CSV output will be saved.
    """

    try:
        df = pd.DataFrame(sbom_data)
        df.to_csv(csv_output_path, index=False)
        print(f"CSV file saved as {csv_output_path}")
    except Exception as e:
        print(f"Error while converting SBOM to CSV: {e}")

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

    def process_item(item):
        if 'components' in item:
            # print(f"Components found:")
            # print(item['components'])

            for library_item in item['components']:
                library_name = library_item.get('name', '')

                if library_name:
                    print(f"Package Name: {library_name}")

                    dependencies.append({
                        'type': 'library',
                        'name': library_name,
                        'version': library_item.get('verson', ''),
                        'dependencies': []
                    })
                #library_version = library_item.get('version', '')
                #library_components = library_item.get('components', [])

                # dep_info = {
                #     'type': 'library',
                #     'name': library_name,
                #     'version': library_version,
                #     'dependencies': []
                # }

                # for component in library_components:
                #     dep_info['dependencies'].append({
                #         'type': 'library',
                #         'name': component.get('name', ''),
                #         'version': component.get('version', '')
                #     })

                # dependencies.append(dep_info)

    def traverse_sbom(sbom_item):
        if 'items' in sbom_item:
            for item in sbom_item['items']:
                process_item(item)
                traverse_sbom(item)

    traverse_sbom(sbom)

    print("CycloneDX SBOM Processed")
    # print(dependencies)
    return dependencies

def validate_sbom(sbom, schema_file):

    with open(schema_file, 'r') as file:
        schema = json.load(file)

    try:
        jsonschema.validate(instance=sbom, schema=schema)
    except jsonschema.exceptions.ValidationError as e:
        print(f"Validation error: {e}")

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
    libraries_and_versions = {}
    for dep in dependencies:
        name = dep.get('name')
        version = dep.get('version')
        if name and version:
            libraries_and_versions[name] = version
            check_vulnerabilities(name)
    print(libraries_and_versions)


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
        csv_output_path = 'sbom_data.csv'
        convert_sbom_to_csv(sbom, csv_output_path)
        print(f"CSV file saved as {csv_output_path}")

        # Check for dependencies and generate dependency tree and vulnerabilities
        if dependencies:
            tree = generate_dependency_tree(dependencies)
            tree.render('dependency_tree.gv', view=True)   
            
            check_all_vulnerabilites(dependencies) # Call check_all_vulnerabilites # Saves and closes the dependency tree
            # Print dependencies to the screen
            print("Dependencies:")
            for dependency in dependencies:
                print(dependency)

            # print("Vulnerabilities Report:", vulnerabilites)
        else:
            print("No dependencies found.")
    else:
        print("Failed to parse SBOM")

if __name__ == "__main__":
    main()