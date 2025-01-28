#!/usr/bin/env python3

import logging
import os

from netbox_manager import NetBoxManager
from config_loader import ConfigLoader
from nmap_scanner import NmapScanner
from fingerprint_engine import FingerprintEngine

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration
NETBOX_URL = os.getenv("NETBOX_URL")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")
SITE_NAME = os.getenv("SITE_NAME")
TENANT_NAME = os.getenv("TENANT_NAME")
SUBNETS = os.getenv("SUBNETS") 
UPDATE_EXISTING = os.getenv("UPDATE_EXISTING", True) 

def main():
    # 1) Initialize NetBox manager, config loader, scanner, fingerprint engine
    nbmgr = NetBoxManager(NETBOX_URL, NETBOX_TOKEN)
    config = ConfigLoader(oui_file="oui.txt", mappings_file="mappings.yaml")
    config.load_all()

    scanner = NmapScanner(enable_os_detection=True)
    fpe = FingerprintEngine(
        config.oui_dict,
        config.port_roles,
        config.fingerprint_patterns
    )

    # 2) For each subnet
    cidr_list = [x.strip() for x in SUBNETS.split(",") if x.strip()]
    # get site ID
    site_obj = nbmgr.nb.dcim.sites.get(name=SITE_NAME)
    if not site_obj:
        logger.error(f"Site '{SITE_NAME}' not found in NetBox.")
        return

    for cidr in cidr_list:
        logger.info(f"=== Processing subnet: {cidr} ===")

        # a) Ensure prefix
        pref = nbmgr.ensure_prefix(cidr, site_id=site_obj.id, update=UPDATE_EXISTING)

        # b) Scan with Nmap
        hosts = scanner.scan_subnet(cidr)
        logger.info(f"Found {len(hosts)} 'up' hosts in {cidr}.")

        for host_info in hosts:
            ip_addr = host_info["ip_addr"]
            mac_addr = host_info["mac_addr"]
            open_ports = host_info["open_ports"]
            platform = host_info["os_guess"] or "Unknown"

            platform_obj = nbmgr.ensure_platform(platform, update=True)

            tenant_obj = nbmgr.ensure_tenant(TENANT_NAME, update=True)

            # c) Fingerprint
            fp = fpe.fingerprint_host(host_info)
            vendor = fp["vendor"]
            role_slug = fp["role_slug"]
            dev_type_model = fp["device_type"]

            logger.debug(f"{ip_addr} => vendor={vendor}, role={role_slug}, dev_type={dev_type_model}")

            # d) NetBox manufacturer
            mfr_obj = nbmgr.ensure_manufacturer(vendor, update=UPDATE_EXISTING)
            # e) device_type
            dev_type_obj = None
            if mfr_obj:
                dev_type_obj = nbmgr.ensure_device_type(dev_type_model, mfr_obj, update=UPDATE_EXISTING)
            # f) device_role
            role_obj = nbmgr.ensure_device_role(role_slug, update=UPDATE_EXISTING)

            # g) device creation
            # host name can be IP if no better name found
            hostname = mac_addr or ip_addr
            if role_obj and dev_type_obj:
                device_obj = nbmgr.ensure_device(
                    hostname,
                    role_obj.id,
                    dev_type_obj.id,
                    site_obj.id,
                    platform_obj.id,
                    tenant_obj.id,
                    update=UPDATE_EXISTING
                )
            else:
                logger.warning(f"Skipping device creation for {ip_addr} because role or devtype missing.")
                continue

            if not device_obj:
                continue

            # h) IP creation
            ip_str = f"{ip_addr}/32"
            ip_obj = nbmgr.ensure_ip(ip_str, update=UPDATE_EXISTING)
            if not ip_obj:
                continue

            for open_port in open_ports:
                nbmgr.ensure_service(device_obj, ip_obj, open_port, 'tcp', update=True)

            # i) interface
            iface_obj = nbmgr.ensure_interface(device_obj.id, if_name="eth0", mac_address=mac_addr, update=UPDATE_EXISTING)

            # j) assign IP to interface
            nbmgr.assign_ip_to_interface(ip_obj, iface_obj)

            # k) set primary IP
            nbmgr.set_primary_ip4(device_obj, ip_obj)

        logger.info(f"=== Finished {cidr} ===\n")

    logger.info("All scans completed.")


if __name__ == "__main__":
    main()

