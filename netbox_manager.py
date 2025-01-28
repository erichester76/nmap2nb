# netbox_manager.py

import logging
import pynetbox

logger = logging.getLogger(__name__)


class NetBoxManager:
    """
    Provides methods for 'get-if-found-then-update-else-create' for
    various NetBox objects. Based on the native .get() and .update()
    approach in pynetbox, but wrapped to reduce code repetition.
    """
    def __init__(self, url, token):
        self.nb = pynetbox.api(url, token=token)

    def ensure_platform(self, platform_name, update=False):
        """
        Get or create a Platform by 'name'.
        E.g., 'Windows', 'Linux', 'FortiOS', etc.
        """
        if not platform_name:
            return None

        # Try to get by name
        platform_obj = self.nb.dcim.platforms.get(name=platform_name)
        if platform_obj:
            if update:
                slug_val = platform_name.lower().replace(' ', '-').replace('.','').replace('(','')
                changes = {}
                if platform_obj.slug != slug_val:
                    changes['slug'] = slug_val
                if changes:
                    try:
                        platform_obj.update(changes)
                        logger.info(f"Updated platform '{platform_name}' with {changes}")
                    except pynetbox.RequestError as e:
                        logger.warning(f"Failed updating platform '{platform_name}': {e}")
            return platform_obj
        else:
            # Create
            slug_val = platform_name.lower().replace(' ', '-').replace('.','').replace('(','')
            data = {
                "name": platform_name,
                "slug": slug_val
            }
            try:
                new_platform = self.nb.dcim.platforms.create(data)
                logger.info(f"Created platform '{platform_name}'")
                return new_platform
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating platform '{platform_name}': {e}")
                return None

    def ensure_service(self, device_obj, ip_obj, port, protocol='tcp', update=False):
        """
        Creates/updates an ipam.services record for a given device and TCP/UDP port.
        - device_obj: the NetBox device object
        - ip_obj: the NetBox IPAddress object (optional, but typically we want to link the IP)
        - port: an integer port number
        - protocol: 'tcp', 'udp', etc. (default = 'tcp')
        - update: bool, if True we update any changed fields on the found service

        Returns the service object or None on error.
        """

        if not device_obj:
            logger.error("No device object provided to ensure_service().")
            return None

        # We'll form a standard name for the service, e.g. "TCP/443"
        svc_name = f"{protocol.upper()}/{port}"

        # We'll try to filter by device_id + name
        existing_services = list(self.nb.ipam.services.filter(
            device_id=device_obj.id,
            name=svc_name
        ))

        if existing_services:
            service = existing_services[0]
            logger.debug(f"Found existing service '{svc_name}' on device '{device_obj.name}'.")
            if update:
                # Build changes
                changes = {}
                # If we want to ensure the list of ports is [port]
                if service.ports != [port]:
                    changes['ports'] = [port]
                if service.protocol != protocol:
                    changes['protocol'] = protocol

                # If we want the IP in ipaddresses
                if ip_obj:
                    current_ips = set(ip.id for ip in service.ipaddresses) if service.ipaddresses else set()
                    if ip_obj.id not in current_ips:
                        new_ip_list = current_ips.union({ip_obj.id})
                        changes['ipaddresses'] = list(new_ip_list)

                if changes:
                    try:
                        service.update(changes)
                        logger.info(f"Updated service '{svc_name}' on {device_obj.name} with {changes}.")
                    except pynetbox.RequestError as e:
                        logger.warning(f"Failed updating service '{svc_name}' on {device_obj.name}: {e}")
            return service
        else:
            # Create a new Service
            data = {
                "device": device_obj.id,
                "name": svc_name,
                "ports": [port],
                "protocol": protocol,
                "description": "Auto-created by Nmap script"
            }
            if ip_obj:
                data["ipaddresses"] = [ip_obj.id]

            try:
                new_svc = self.nb.ipam.services.create(data)
                logger.info(f"Created new service '{svc_name}' on device '{device_obj.name}'.")
                return new_svc
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating service '{svc_name}' on {device_obj.name}: {e}")
                return None

    def ensure_prefix(self, prefix_str, site_id=None, update=False):
        """
        Attempt to get the prefix by 'prefix=prefix_str'.
        If not found, create it.
        If found and update=True, update fields if needed.
        """
        existing = self.nb.ipam.prefixes.get(prefix=prefix_str)
        if existing:
            logger.debug(f"Found prefix {prefix_str}")
            if update and site_id:
                changes = {}
                existing_scope_type = getattr(existing, 'scope_type', None)
                existing_scope_id = getattr(existing, 'scope_id', None)

                # If it's already set to 'dcim.site' with the same ID, no change needed
                if existing_scope_type != 'dcim.site' or existing_scope_id != site_id:
                    changes['scope_type'] = 'dcim.site'
                    changes['scope_id'] = site_id

                if changes:
                    try:
                        existing.update(changes)
                        logger.info(f"Updated prefix {prefix_str} scope to site_id {site_id}")
                    except pynetbox.RequestError as e:
                        logger.warning(f"Failed updating prefix {prefix_str} scope: {e}")
            return existing
        else:
            # create
            data = {"prefix": prefix_str}
            if site_id:
                data["site"] = site_id
            try:
                created = self.nb.ipam.prefixes.create(data)
                logger.info(f"Created prefix {prefix_str}")
                return created
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating prefix {prefix_str}: {e}")
                return None

    def ensure_tenant(self, name, update=False):
        """
        Get by name; if not found, create. If found and update=True, see if we must update slug or so.
        """
        existing = self.nb.tenancy.tenants.get(name=name)
        if existing:
            logger.debug(f"Found tenant {name}")
            if update:
                # You might compare slug or other fields
                pass
            return existing
        else:
            slug_val = name.lower().replace(" ", "-")
            data = {"name": name, "slug": slug_val}
            try:
                created = self.nb.tenancy.tenants.create(data)
                logger.info(f"Created tenant '{name}'")
                return created
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating tenant '{name}': {e}")
                return None

    def ensure_manufacturer(self, name, update=False):
        """
        Get by name; if not found, create. If found and update=True, see if we must update slug or so.
        """
        existing = self.nb.dcim.manufacturers.get(name=name)
        if existing:
            logger.debug(f"Found manufacturer {name}")
            if update:
                # You might compare slug or other fields
                pass
            return existing
        else:
            slug_val = name.lower().replace(" ", "-")
            data = {"name": name, "slug": slug_val}
            try:
                created = self.nb.dcim.manufacturers.create(data)
                logger.info(f"Created manufacturer '{name}'")
                return created
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating manufacturer '{name}': {e}")
                return None

    def ensure_device_type(self, model, manufacturer_obj, update=False):
        """
        Get by model + manufacturer_id. If none, create.
        If found and update=True, compare fields if needed.
        """
        if not manufacturer_obj:
            logger.warning("No manufacturer_obj provided for device_type. Cannot proceed.")
            return None

        existing = self.nb.dcim.device_types.filter(
            model=model, manufacturer_id=manufacturer_obj.id
        )
        existing = list(existing)  # filter returns a generator-like object
        if existing:
            dt = existing[0]
            logger.debug(f"Found device_type '{model}' under '{manufacturer_obj.name}'")
            if update:
                # compare fields as needed
                pass
            return dt
        else:
            slug_val = model.lower().replace(" ", "-")
            data = {
                "model": model,
                "slug": slug_val,
                "manufacturer": manufacturer_obj.id
            }
            try:
                created = self.nb.dcim.device_types.create(data)
                logger.info(f"Created device_type '{model}' under '{manufacturer_obj.name}'")
                return created
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating device_type '{model}': {e}")
                return None

    def ensure_device_role(self, slug, update=False):
        """
        Get by slug or name. If none, create.
        """
        existing = list(self.nb.dcim.device_roles.filter(slug=slug))
        if existing:
            dr = existing[0]
            logger.debug(f"Found device_role '{slug}'")
            if update:
                # compare fields
                pass
            return dr
        else:
            data = {
                "name": slug.capitalize(),
                "slug": slug
            }
            try:
                created = self.nb.dcim.device_roles.create(data)
                logger.info(f"Created device_role '{slug}'")
                return created
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating device_role '{slug}': {e}")
                return None

    def ensure_device(self, name, role_id, device_type_id, site_id, platform_id, tenant_id, update=False):
        """
        Get device by name; if none, create it.
        If found and update=True, we update role/device_type if needed.
        """
        existing = self.nb.dcim.devices.get(name=name)
        if existing:
            logger.debug(f"Found device '{name}'")
            if update:
                changes = {}
                if role_id and existing.role and existing.role.id != role_id:
                    changes['role'] = role_id
                if device_type_id and existing.device_type and existing.device_type.id != device_type_id:
                    changes['device_type'] = device_type_id
                if platform_id and existing.platform != platform_id:
                    changes["platform"] = platform_id
                if tenant_id and existing.tenant != tenant_id:
                    changes["tenant"] = tenant_id
                if changes:
                    try:
                        existing.update(changes)
                        logger.info(f"Updated device '{name}' with {changes}")
                    except pynetbox.RequestError as e:
                        logger.warning(f"Failed updating device '{name}': {e}")
            return existing
        else:
            data = {
                "name": name,
                "role": role_id,
                "device_type": device_type_id,
                "site": site_id,
                "tenant": tenant_id,
                "platform": platform_id,
            }
            try:
                created = self.nb.dcim.devices.create(data)
                logger.info(f"Created device '{name}'")
                return created
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating device '{name}': {e}")
                return None

    def ensure_ip(self, ip_str, update=False):
        """
        Get IP by address. If none, create.
        """
        existing = self.nb.ipam.ip_addresses.get(address=ip_str)
        if existing:
            logger.debug(f"Found IP '{ip_str}'")
            # update if needed
            return existing
        else:
            data = {"address": ip_str}
            try:
                created = self.nb.ipam.ip_addresses.create(data)
                logger.info(f"Created IP '{ip_str}'")
                return created
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating IP '{ip_str}': {e}")
                return None

    def ensure_interface(self, device_id, if_name="eth0", mac_address=None, update=False):
        """
        If we find an interface by device_id + name, or device_id + mac, we re-use it.
        Otherwise we create. Then optionally update.
        """
        # Minimal approach: first try filter by device_id + name
        existing_list = list(self.nb.dcim.interfaces.filter(device_id=device_id, name=if_name))
        if existing_list:
            iface = existing_list[0]
            logger.debug(f"Found interface '{if_name}' on device_id={device_id}")
            if update:
                changes = {}
                if mac_address and iface.mac_address and iface.mac_address.lower() != mac_address.lower():
                    changes['mac_address'] = mac_address
                if changes:
                    try:
                        iface.update(changes)
                        logger.info(f"Updated interface '{if_name}' with {changes}")
                    except pynetbox.RequestError as e:
                        logger.warning(f"Failed updating interface '{if_name}': {e}")
            return iface
        else:
            data = {
                "device": device_id,
                "name": if_name,
                "type": "1000base-t"
            }
            if mac_address:
                data["mac_address"] = mac_address
            try:
                created = self.nb.dcim.interfaces.create(data)
                logger.info(f"Created interface '{if_name}' on device_id={device_id}")
                return created
            except pynetbox.RequestError as e:
                logger.error(f"Failed creating interface '{if_name}': {e}")
                return None

    def assign_ip_to_interface(self, ip_obj, iface_obj):
        """
        NetBox 4.x style: assigned_object_type='dcim.interface' + assigned_object_id
        """
        if not ip_obj or not iface_obj:
            return
        if not ip_obj.assigned_object_id:
            try:
                ip_obj.update({
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": iface_obj.id
                })
                logger.info(f"Assigned IP {ip_obj.address} to interface {iface_obj.name}")
            except pynetbox.RequestError as e:
                logger.warning(f"Failed assigning IP {ip_obj.address} to {iface_obj.name}: {e}")

    def set_primary_ip4(self, device_obj, ip_obj):
        """Set device's primary_ip4 to ip_obj.id."""
        if device_obj and ip_obj and device_obj.primary_ip4 != ip_obj.id:
            try:
                device_obj.update({"primary_ip4": ip_obj.id})
                logger.info(f"Set primary IP of device '{device_obj.name}' to {ip_obj.address}")
            except pynetbox.RequestError as e:
                logger.warning(f"Failed setting primary IP for '{device_obj.name}': {e}")

