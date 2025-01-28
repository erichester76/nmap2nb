# fingerprint_engine.py

import logging
import re
import ssl
import socket
import requests

logger = logging.getLogger(__name__)

DEFAULT_VENDOR = "Unknown"
DEFAULT_ROLE_SLUG = "unknown"
DEFAULT_DEVICE_TYPE = "Unknown"

class FingerprintEngine:
    """
    Decides vendor, role slug, device_type based on:
      - MAC prefix (OUI)
      - Open ports mapping
      - OS guess
      - TLS certificate CN + page content
      - External regex patterns
    """
    def __init__(self, oui_dict, port_roles, fingerprint_patterns):
        self.oui_dict = oui_dict
        self.port_roles = port_roles
        self.fingerprint_patterns = fingerprint_patterns

    def fingerprint_host(self, host_data):

        ip_addr = host_data["ip_addr"]
        mac = host_data["mac_addr"]
        open_ports = host_data["open_ports"]
        os_guess = host_data["os_guess"]

        vendor = DEFAULT_VENDOR
        role_slug = DEFAULT_ROLE_SLUG
        device_type = DEFAULT_DEVICE_TYPE

        # 1) OUI
        if mac:
            prefix = mac[:8].upper()
            maybe_vendor = self.oui_dict.get(prefix)
            if maybe_vendor:
                logger.debug(f"Found {maybe_vendor} from OUI")
                vendor = maybe_vendor

        # 2) Port-based
        # If multiple ports match, we take the first. Adjust as needed.
        for p in open_ports:
            # port_roles is e.g. { "22": { role=..., device_type=...}, ... }
            p_str = str(p)
            if p_str in self.port_roles:
                role_slug = self.port_roles[p_str].get("role", role_slug)
                device_type = self.port_roles[p_str].get("device_type", device_type)
                logger.debug(f"Found {role_slug}, {device_type} from Ports")

                break

        # 3) If port 443 in open_ports, do certificate/page inspection if vendor==Generic or device_type==GenericModel
        if 443 in open_ports and (vendor == DEFAULT_VENDOR or device_type == DEFAULT_DEVICE_TYPE):
            cn, page_txt = self._fetch_cert_and_page(ip_addr, 443)
            v2, dt2 = self._regex_fingerprint(cn, page_txt)
            logger.debug(f"Found {v2}, {dt2} from TLS")
            if v2 and vendor == DEFAULT_VENDOR:
                vendor = v2
            if dt2 and device_type == DEFAULT_DEVICE_TYPE:
                device_type = dt2

        # 4) OS guess to refine vendor if still "Generic"
        if vendor == DEFAULT_VENDOR and os_guess:
            lower_os = os_guess.lower()

        return {
            "vendor": vendor,
            "role_slug": role_slug,
            "device_type": device_type
        }

    def _fetch_cert_and_page(self, ip, port=443, timeout=3):
        """Return (cert_cn, page_text)."""
        cert_cn = ""
        page_text = ""
        # TLS CN
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    subject = cert.get("subject", [])
                    for item in subject:
                        if item[0][0] == "commonName":
                            cert_cn = item[0][1].lower()
                            break
        except Exception as e:
            logger.debug(f"TLS CN fetch failed for {ip}:{port}: {e}")

        # Page
        try:
            url = f"https://{ip}:{port}"
            r = requests.get(url, verify=False, timeout=timeout)
            page_text = r.text.lower()
        except Exception as e:
            logger.debug(f"HTTPS page fetch failed for {ip}:{port}: {e}")

        return (cert_cn, page_text)

    def _regex_fingerprint(self, cert_cn, page_text):
        """
        Use self.fingerprint_patterns to see if combined text matches
        a known vendor/device_type. Return (vendor, device_type) or (None, None).
        """
        combined = (cert_cn or "") + " " + (page_text or "")
        if not combined.strip():
            return (None, None)

        for entry in self.fingerprint_patterns:
            pat = entry.get("regex")
            vend = entry.get("vendor")
            dt = entry.get("device_type")
            if pat and vend and dt:
                if re.search(pat, combined):
                    return (vend, dt)
        return (None, None)

