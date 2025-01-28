# nmap_scanner.py

import logging
import nmap


logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self, enable_os_detection=True):
        self.nm = nmap.PortScanner()
        self.enable_os_detection = enable_os_detection

    def scan_subnet(self, cidr):
        """
        Returns a list of dicts for each 'up' host:
        [
          {
            "ip_addr": str,
            "mac_addr": str or None,
            "open_ports": [int, ...],
            "os_guess": str or None
          }, ...
        ]
        """
        args = "--top-ports 1000 -sS -T4"
        if self.enable_os_detection:
            args += " -O"

        logger.info(f"Scanning {cidr} with args '{args}'")
        self.nm.scan(cidr, arguments=args)

        results = []
        for host in self.nm.all_hosts():
            if self.nm[host].state() == "up":
                ip_addr = self.nm[host]["addresses"].get("ipv4", host)
                mac_addr = self.nm[host]["addresses"].get("mac")
                # gather open TCP ports
                open_ports = []
                if "tcp" in self.nm[host]:
                    for p, pdata in self.nm[host]["tcp"].items():
                        if pdata["state"] == "open":
                            open_ports.append(int(p))

                # OS guess
                os_guess = None
                if self.enable_os_detection and "osmatch" in self.nm[host]:
                   osmatch_list = self.nm[host].get('osmatch', [])
                   best_accuracy = 0
                   best_name = None
                   for entry in osmatch_list:
                       accuracy_str = entry.get('accuracy', '0')
                       try:
                           accuracy_val = int(accuracy_str)
                       except ValueError:
                            accuracy_val = 0

                       if accuracy_val > best_accuracy:
                            best_accuracy = accuracy_val
                            best_name = entry.get('name', None)[:25]

                   if best_accuracy >= 85 and best_name:
                       os_guess = best_name
                   else:
                       os_guess = None


                results.append({
                    "ip_addr": ip_addr,
                    "mac_addr": mac_addr,
                    "open_ports": open_ports,
                    "os_guess": os_guess
                })
        return results

