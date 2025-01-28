# config_loader.py

import os
import logging
import yaml

logger = logging.getLogger(__name__)

class ConfigLoader:
    def __init__(self, oui_file="oui.txt", mappings_file="mappings.yaml"):
        self.oui_dict = {}
        self.port_roles = {}
        self.fingerprint_patterns = []
        self.oui_file = oui_file
        self.mappings_file = mappings_file

    def load_all(self):
        self.load_oui()
        self.load_mappings()

    def load_oui(self):
        if not os.path.isfile(self.oui_file):
            logger.warning(f"OUI file '{self.oui_file}' not found; MAC lookups may be 'Unknown'.")
            return

        with open(self.oui_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) == 2:
                    mac_prefix, vendor = parts
                    self.oui_dict[mac_prefix] = vendor.strip()
                elif len(parts) >= 3:
                    mac_prefix, _, vendor = parts[0], parts[1], parts[2]
                    self.oui_dict[mac_prefix] = vendor.strip()

    def load_mappings(self):
        if not os.path.isfile(self.mappings_file):
            logger.error(f"Mappings file '{self.mappings_file}' not found; using defaults.")
            return
        with open(self.mappings_file, 'r') as f:
            data = yaml.safe_load(f) or {}
        self.port_roles = data.get("port_roles", {})
        self.fingerprint_patterns = data.get("fingerprint_patterns", [])

