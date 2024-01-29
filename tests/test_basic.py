# test_basic.py
import json
import unittest
from unittest.mock import patch, MagicMock, mock_open
import xml.etree.ElementTree as ET
from src.main import parse_sbom_json, parse_sbom_xml, check_vulnerabilities, process_sbom

class TestSBOMProcessing(unittest.TestCase):

    def test_parse_sbom_json(self):
        with open('bom.json', 'r') as file:
            mock_data = file.read()

        with patch("builtins.open", mock_open(read_data=mock_data)):
            sbom = parse_sbom_json('bom.json')
            # Assertions based on your actual bom.json structure
            self.assertIn('dependencies', sbom)
            self.assertIsInstance(sbom['dependencies'], list)
            # Add more assertions based on expected content of bom.json

    def test_parse_sbom_xml(self):
        # Mock XML data for parsing (structure matches the provided bom.xml)
        mock_xml_data = '''
    <bom xmlns="http://cyclonedx.org/schema/bom/1.2">
        <metadata>
            <project>
                <name>Sample Project</name>
                <version>1.0</version>
            </project>
        </metadata>
        <components>
            <component>
                <name>Library A</name>
                <version>1.2.3</version>
            </component>
            <component>
                <name>Library B</name>
                <version>2.0.1</version>
            </component>
            <!-- Add more components as needed -->
        </components>
    </bom>
'''

        # Use the actual bom.xml for parsing or mock it if you are not using a real file
        with patch("xml.etree.ElementTree.parse") as mock_parse:
            mock_parse.return_value.getroot.return_value = ET.fromstring(mock_xml_data)
            sbom = parse_sbom_xml('bom.xml')
    
        # Assertions based on the updated XML structure
        self.assertIsNotNone(sbom.find('{http://cyclonedx.org/schema/bom/1.2}metadata'))
        self.assertIsNotNone(sbom.find('{http://cyclonedx.org/schema/bom/1.2}components'))
        # Add more assertions based on expected content of bom.xml

    def test_generate_dependency_tree(self):
        # Prepare sample SBOM data (replace with your actual data structure)
        sample_sbom = [
            {
                'name': 'Library A',
                'version': '1.0',
                'dependencies': [
                    {'name': 'Library B'},
                    {'name': 'Library C'},
                ]
            },
            {
                'name': 'Library B',
                'version': '2.0',
                'dependencies': [
                    {'name': 'Library D'},
                ]
            },
        ]

        # Call the generate_dependency_tree function with the sample data
        dependency_tree = generate_dependency_tree(sample_sbom)

        # Add assertions to check if the generated tree matches your expectations
        # For example, you can check if specific nodes and edges exist:
        self.assertTrue(dependency_tree.node('Library A'))
        self.assertTrue(dependency_tree.node('Library B'))
        self.assertTrue(dependency_tree.edge('Library A', 'Library B'))

    @patch('requests.get')
    def test_check_vulnerabilities(self, mock_get):
        # Example response from a vulnerability check
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": [{"id": "CVE-1234", "severity": "high"}]}
        mock_get.return_value = mock_response

        vulnerabilities = check_vulnerabilities("library1")
        mock_get.assert_called_with('https://vulndb.com/api/library1')
        self.assertIn("vulnerabilities", vulnerabilities)
        self.assertEqual(vulnerabilities["vulnerabilities"][0]["id"], "CVE-1234")

    def test_process_sbom(self):
        # You might need to parse your bom.json or bom.xml first to pass as an argument to process_sbom
        with open('bom.json', 'r') as file:
            mock_data = {
            'dependencies': [
                {'ref': '256eb631-b99b-4a57-b399-997ec5254dec', 'dependsOn': []}
            ]
        }

        # Mock the process_sbom function behavior if needed, or call directly if it's pure function
        dependencies = process_sbom(mock_data)
        # Assertions based on your actual dependencies structure
        self.assertIsInstance(dependencies, list)
        self.assertGreater(len(dependencies), 0)
        self.assertIn('ref', dependencies[0])
        self.assertIn('dependencies', dependencies[0])

        # Add more assertions based on expected content of dependencies

if __name__ == '__main__':
    unittest.main()
