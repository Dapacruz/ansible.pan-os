#!/usr/bin/env python3

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import ssl
import sys
from collections import defaultdict
from urllib import parse
from urllib.request import urlopen

import xmltodict
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin

DOCUMENTATION = r"""
    name: panorama_plugin
    plugin_type: inventory
    short_description: Returns Ansible inventory from Panorama
    description: Returns Ansible inventory from Panorama
    options:
      plugin:
          description: Get Panorama connected firewalls
          required: true
          choices: ['panorama_plugin']
"""

panorama_api_token = os.environ["panw_api_token"]


class InventoryModule(BaseInventoryPlugin):
    NAME = "panorama_plugin"

    def verify_file(self, path):
        """return true/false if this is possibly a valid file for this plugin to consume"""
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(("panorama_inventory.yaml", "panorama_inventory.yml")):
                return True
        return False

    def _get_firewalls(self):
        # Disable certifcate verification
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Get connected firewalls
        cmd = "<show><devices><connected></connected></devices></show>"
        params = parse.urlencode(
            {
                "type": "op",
                "cmd": cmd,
                "key": panorama_api_token,
            }
        )
        url = f"https://{self.panorama}/api/?{params}"
        try:
            with urlopen(url, context=ctx) as response:
                xml = response.read().decode("utf-8")
        except OSError as err:
            sys.stderr.write(f"{self.panorama}: Unable to connect to host ({err})\n")
            sys.exit(1)

        return xml

    def _get_structured_inventory(self):
        xml = self._get_firewalls()
        firewalls = xmltodict.parse(xml)["response"]["result"]["devices"]["entry"]
        return firewalls

    def _get_tags(self):
        # Disable certifcate verification
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Get firewall tags
        params = parse.urlencode(
            {
                "type": "config",
                "action": "get",
                "xpath": "/config/mgt-config",
                "key": panorama_api_token,
            }
        )
        url = f"https://{self.panorama}/api/?{params}"
        try:
            with urlopen(url, context=ctx) as response:
                xml = response.read().decode("utf-8")
        except OSError as err:
            sys.stderr.write(f"{self.panorama}: Unable to connect to host ({err})\n")
            sys.exit(1)

        return xml

    def _get_structured_tags(self):
        xml = self._get_tags()
        tag_data = xmltodict.parse(xml)["response"]["result"]["mgt-config"]["devices"][
            "entry"
        ]
        tags = defaultdict(set)
        for sn in tag_data:
            if type(sn["vsys"]["entry"]) is list:
                for vsys in sn["vsys"]["entry"]:
                    if type(vsys["tags"]["member"]) is list:
                        tags[sn["@name"]].update(vsys["tags"]["member"])
                    else:
                        tags[sn["@name"]].add(vsys["tags"]["member"])
            else:
                if type(sn["vsys"]["entry"]["tags"]["member"]) is list:
                    tags[sn["@name"]].update(sn["vsys"]["entry"]["tags"]["member"])
                else:
                    tags[sn["@name"]].add(sn["vsys"]["entry"]["tags"]["member"])
        return tags

    def _populate(self):
        """Return the hosts and groups"""
        self.inventory.add_group("active")
        self.inventory.add_group("passive")
        self.inventory.add_group("nam")
        self.inventory.add_group("intl")
        self.inventory.add_group("test")
        self.inventory.add_group("rkat1_datacenter")
        self.inventory.add_group("sast1_datacenter")
        self.inventory.add_group("asbc1_datacenter")

        tags = self._get_structured_tags()
        firewalls = self._get_structured_inventory()
        for fw in firewalls:
            fw_tags = [tag.lower() for tag in tags.get(fw["serial"], [])]
            if any(item in ["staging", "disable-ansible"] for item in fw_tags):
                continue
            elif len(fw_tags) == 0:
                continue

            ha_state = fw.get("ha", {}).get("state", "standalone")
            if ha_state == "passive":
                self.inventory.add_host(host=fw["hostname"], group="passive")
            else:
                self.inventory.add_host(host=fw["hostname"], group="active")

            if "nam" in fw_tags:
                self.inventory.add_host(host=fw["hostname"], group="nam")
            elif "intl" in fw_tags:
                self.inventory.add_host(host=fw["hostname"], group="intl")

            if "test" in fw_tags:
                self.inventory.add_host(host=fw["hostname"], group="test")

            if fw["hostname"].startswith("RKAT1"):
                self.inventory.add_host(host=fw["hostname"], group="rkat1_datacenter")
            elif fw["hostname"].startswith("SAST1"):
                self.inventory.add_host(host=fw["hostname"], group="sast1_datacenter")
            elif fw["hostname"].startswith("ASBC1"):
                self.inventory.add_host(host=fw["hostname"], group="asbc1_datacenter")

            self.inventory.set_variable(
                fw["hostname"], "ansible_host", f'{fw["hostname"].lower()}.***REMOVED***'
            )
            self.inventory.set_variable(fw["hostname"], "serial_number", fw["serial"])
            self.inventory.set_variable(fw["hostname"], "model_number", fw["model"])
            self.inventory.set_variable(
                fw["hostname"], "tags", f'[{", ".join(tags.get(fw["serial"], []))}]'
            )
            self.inventory.set_variable(fw["hostname"], "ha_state", ha_state)

    def parse(self, inventory, loader, path, cache):
        """Return dynamic inventory from source"""
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        # Read the inventory YAML file
        self._read_config_data(path)
        try:
            # Store the options from the YAML file
            self.plugin = self.get_option("plugin")
            # self.panorama = self.get_option("self.panorama")
            self.panorama = "***REMOVED***"
        except Exception as e:
            raise AnsibleParserError(f"All correct options required: {e}")

        # Call our internal helper to populate the dynamic inventory
        self._populate()
