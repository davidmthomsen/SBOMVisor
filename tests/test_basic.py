# test_basic.py
import json
import unittest
from unittest.mock import patch, MagicMock, mock_open
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
        # Use the actual bom.xml for parsing
        sbom = parse_sbom_xml('bom.xml')
        # Assertions based on your actual bom.xml structure
        self.assertIsNotNone(sbom.find('.//dependency'))
        # Add more assertions based on expected content of bom.xml

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
            mock_data = json.load(file)

        # Mock the process_sbom function behavior if needed, or call directly if it's pure function
        dependencies = process_sbom(mock_data)
        # Assertions based on your actual dependencies structure
        self.assertIsInstance(dependencies, list)
        # Add more assertions based on expected content of dependencies

if __name__ == '__main__':
    unittest.main()
