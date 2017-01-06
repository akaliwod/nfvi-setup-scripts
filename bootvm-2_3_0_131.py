#!/usr/bin/env python
from __future__ import print_function

import argparse
import copy
import json
import logging
import os
import random
import re
import shutil
import six
import socket
import string
import subprocess
import sys
import traceback
import crypt
import random
import time
import base64
import getpass

import xml.dom.minidom
import xml.etree.cElementTree as ET

from netaddr import *

sys.path.append('/usr/share/virt-manager')

BOOTVM_VERSION = "ESC-2_3_0_131"

LogLevelMap = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'WARN': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG
}

"""
Exception definitions.
"""
class BootVMException(Exception):
    """Base Tempest Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = "An unknown exception occurred"

    def __init__(self, *args, **kwargs):
        super(BootVMException, self).__init__()
        try:
            self._error_string = self.message % kwargs
        except Exception as e:
            # at least get the core message out if something happened
            self._error_string = self.message
        if len(args) > 0:
            # If there is a non-kwarg parameter, assume it's the error
            # message or reason description and tack it on to the end
            # of the exception message
            # Convert all arguments into their string representations...
            args = ["%s" % arg for arg in args]
            self._error_string = (self._error_string +
                                  "\nDetails: %s" % '\n'.join(args))

    def __str__(self):
        return self._error_string

class NoneValue(BootVMException):
    message = "%(name)s is None"

class InvalidVolumeStatus(BootVMException):
    message = "You cannot use the volume %(volume)s in '%(status)s' status."

class InvalidHaMode(BootVMException):
    message = "%(ha_mode)s is an invalid HA mode. Valid HA mode: 1: cinder, 2: drbd, 3: drbd_on_cinder."

class InvalidServer(BootVMException):
    message = "%(name)s: server not found."

class InvalidServerGroup(BootVMException):
    message = "%(name)s: server group not found."

class InvalidVolume(BootVMException):
    message = "Cannot retrieve volume: %(host)s"

class InvalidUserPassFormat(BootVMException):
    message = "invalid format for --user_pass %(upk)s."

class MissingCredentials(BootVMException):
    message = "missing bs_os_auth_url or libvirt. Do not know how to boot ESC. Check command line or source openrc first."

class MissingKadVri(BootVMException):
    message = "The kad virtual router id is needed for ESC HA. Please specify it with '--kad_vri'"

class MissingHaNodeList(BootVMException):
    message = "missing ha_node_list. It's mandatory in HA mode drbd or drbd_on_cinder."

class MissingUserKey(BootVMException):
    message = "key file '%(key)s' doesn't exist."

class InvalidateNetwork(BootVMException):
    message = "Unable to find network with name or id '%(net)s'."

class MultipleNetwork(BootVMException):
    message = "Multiple network matches found for name '%(net)s', use an ID to be more specific."

class MissingImage(BootVMException):
    message = "Image %(image)s not found."

class MissingUserPassKey(BootVMException):
    message = "--secure option is given. ESC VM is not accessible without a key. Please specify the public key by '--user_pass'."

class DuplicatedHostName(BootVMException):
    message = "There is already a server with name '%(host)s'. Please use another name."

class ServerInErrorState(BootVMException):
    message = "'%(name)s was not booted properly'. Please check the details by nova show %(id)s."

class InvalidArgument(BootVMException):
    message = "ERROR: unrecognized argument: %(name)s"

vmm = None

# Used for self test
vmm_vnf  = None

class VMManager(object):
    def __init__(self, args):
        self.bs_os_auth_url      = args.bs_os_auth_url
        self.bs_os_tenant_name   = args.bs_os_tenant_name
        self.bs_os_username      = args.bs_os_username
        self.bs_os_password      = args.bs_os_password

        self.os_auth_url      = args.os_auth_url
        self.os_tenant_name   = args.os_tenant_name
        self.os_username      = args.os_username
        self.os_password      = args.os_password

        # Handle default value assignment for OpenStack credentials (openrc)
        if self.os_auth_url is None:
           self.os_auth_url = self.bs_os_auth_url
        if self.os_tenant_name is None:
           self.os_tenant_name = self.bs_os_tenant_name
        if self.os_username is None:
           self.os_username = self.bs_os_username
        if self.os_password is None:
           self.os_password = self.bs_os_password

class OSManager(VMManager):
    def __init__(self, args):
        super(OSManager, self).__init__(args)

        if not self.bs_os_auth_url or len(self.bs_os_auth_url) == 0:
            raise MissingCredentials()

        # append / to end of os_auth_url
        if not self.os_auth_url.endswith('/'):
            self.os_auth_url += '/'
        if not self.bs_os_auth_url.endswith('/'):
            self.bs_os_auth_url += '/'

    def __getattr__(self, attr):
        if attr in self.__dict__:
            return self.__dict__[attr]

        if attr == 'nova':
            from novaclient import client as novaclient

            self.nova = novaclient.Client('2', *self.getBootstrapOpenStackCredentials())
        elif attr == 'neutron':
            from neutronclient.v2_0 import client as neutronclient

            self.neutron = neutronclient.Client(username=self.bs_os_username,
                                    password=self.bs_os_password,
                                    tenant_name=self.bs_os_tenant_name,
                                    auth_url=self.bs_os_auth_url)
        elif attr == 'cinder':
            from cinderclient import client as cinderclient

            self.cinder = cinderclient.Client('1', self.bs_os_username,
                        self.bs_os_password,
                        self.bs_os_tenant_name,
                        self.bs_os_auth_url)
        elif attr == 'glance':
            from glanceclient import client as glanceclient

            #self.glance = glanceclient.Client()
        elif attr == 'keystone':
            try:
                from keystoneauth1.identity import v2
                from keystoneauth1 import session
                from keystoneclient.v2_0 import client as keystoneclient

                auth = v2.Password(username=self.bs_os_username,
                                        password=self.bs_os_password,
                                        tenant_name=self.bs_os_tenant_name,
                                        auth_url=self.bs_os_auth_url)

                sess = session.Session(auth=auth)
                self.keystone = keystoneclient.Client(session=sess)
            except Exception as ex:
                from keystoneclient import client as keystoneclient

                self.keystone = keystoneclient.Client(username=self.bs_os_username,
                                    password=self.bs_os_password,
                                    tenant_name=self.bs_os_tenant_name,
                                    auth_url=self.bs_os_auth_url)
        else:
            return None

        return self.__dict__[attr]

    def getBootstrapOpenStackCredentials(self):
        return self.bs_os_username, self.bs_os_password, self.bs_os_tenant_name, self.bs_os_auth_url

    # Only used for testing
    def get_tenant(self, tenant):
        for t in self.keystone.tenants.list():
            if t.name == tenant:
                return t

        return None

    def get_image(self, image):
        from novaclient import utils as nova_utils

        return nova_utils.find_resource(self.nova.images, image)

    def get_flavor(self, flavor):
        from novaclient import utils as nova_utils

        return nova_utils.find_resource(self.nova.flavors, flavor)

    def list_networks(self, **params):
        return self.neutron.list_networks(**params)

    def get_network(self, net):
        networks = self.list_networks(id=net)['networks']

        if len(networks) == 1:
            return {'network': networks[0]}

        networks = self.list_networks(name=net)['networks']

        if len(networks) == 1:
            return {'network': networks[0]}

        return None

    def get_subnet(self, subnet):
        return self.neutron.show_subnet(subnet)

    def update_port(self, port, payload):
        return self.neutron.update_port(port, payload)

    def get_port(self, network_id=None, ip=None, device_id=None):
        ports = []

        for port in self.neutron.list_ports(fields=('id', 'network_id', 'fixed_ips', 'device_id'))['ports']:
            if network_id is not None and port['network_id'] != network_id:
                continue

            if ip is not None and port['fixed_ips'][0]['ip_address'] != ip:
                continue

            if device_id  is not None and port['device_id'] != device_id:
                continue

            ports.append(port)

        if len(ports) == 0:
            return None
        else:
            return ports

    def get_gateway_ip(self, net, ip):
        network = self.get_network(net)['network']

        for subnet_id in network['subnets']:
            subnet = self.get_subnet(subnet_id)['subnet']

            if IPNetwork(subnet['cidr']).__contains__(ip):
                return subnet['gateway_ip']

        return None

    def list_servers(self, **params):
        return self.nova.servers.list()

    def get_server_groups(self, **params):
        return self.nova.server_groups.list()

    def get_server_group(self, name):
        for server_group in self.get_server_groups():
            if server_group.name == name:
                return server_group

            if server_group.id == name:
                return server_group

        return None

    def get_server(self, name):
        for server in self.list_servers():
            if server.name == name:
                return server

            if server.id == name:
                return server

        return None

    def delete_server(self, server):
        from novaclient import utils as nova_utils

        if hasattr(server, 'delete'):
            server.delete()
            return

        server = nova_utils.find_resource(self.nova.servers, server)
        server.delete()

    def create_server(self, name=None, image=None, flavor=None, files=None, userdata=None, poll=None, avail_zone=None, net=None, ipaddr=None, volume=None, hints={}):
        boot_args = [name, self.get_image(image), self.get_flavor(flavor)]

        nics = []
        for idx, net, ipaddr in enumerateNetIP(net, ipaddr):
            nic = {}
            nic['net-id'] = self.get_network(net)['network']['id']

            if ipaddr is not None:
                ports = self.get_port(network_id = nic['net-id'], ip = str(ipaddr.ip))

                if ports is None:
                    if ipaddr.version == 4:
                        nic['v4-fixed-ip'] = str(ipaddr.ip)
                    else:
                        nic['v6-fixed-ip'] = str(ipaddr.ip)
                else:
                    nic['port-id'] = ports[0]['id']

            nics.append(nic)

        block_device_mapping = None

        if volume is not None:
            block_device_mapping = {"vdb": "%s:::0" % volume}

        boot_kwargs = dict(
            min_count=1,
            max_count=1,
            files=files,
            nics=nics,
            userdata=userdata,
            availability_zone=avail_zone,
            block_device_mapping=block_device_mapping,
            scheduler_hints=hints,
            config_drive=True)

        server = self.nova.servers.create(*boot_args, **boot_kwargs)

        while True:
            server = self.nova.servers.get(server.id)
            status = getattr(server, 'status')

            if status:
                status = status.lower()

            progress = getattr(server, 'progress', None) or 0

            if status == 'active':
                break
            elif status == "error":
                break
            elif status == "deleted":
                break

            time.sleep(5)

        return server

    def create_volume(self, name="esc-db", size=1):
        volume = self.cinder.volumes.create(size, display_name=name)

        return volume

    def get_volume(self, volume):
        volume = self.cinder.volumes.get(volume)

        return volume

    def create_port(self, net, port_name=None, ip=None):
        body_value = { "port": {
                        "admin_state_up": True,
                        "name": port_name,
                        "network_id": self.get_network(net)['network']['id']
                                }
                        }
        if not ip is None:
            body_value['port']['fixed_ips'] = [{"ip_address": ip}]

        return self.neutron.create_port(body=body_value)['port']

class LibVirtManager(VMManager):
    def __init__(self, args):
        super(LibVirtManager, self).__init__(args)

        import libvirt

        """
        Ignore libvirt error reporting, we just use exceptions
        """
        def libvirt_callback(userdata, err):
            ignore = userdata
            ignore = err

        libvirt.registerErrorHandler(f=libvirt_callback, ctx=None)

        try:
            import virtinst
            self.conn = virtinst.cli.getConnection(args.libvirt)
        except Exception as ex:
            self.conn = libvirt.open(None)
            #import virtinst.cli as cli
            #self.conn = cli.getConnection(args.libvirt)

    def get_flavor(self, flavor):
        # predefined flavors
        m1_tiny={"name": "m1.tiny", "mem": 512, "vcpus": 1}
        m1_small={"name": "m1.small", "mem": 2048, "vcpus": 1}
        m1_medium={"name": "m1.medium", "mem": 4096, "vcpus": 2}
        m1_large={"name": "m1.large", "mem": 8192, "vcpus": 4}
        m1_xlarge={"name": "m1.xlarge", "mem": 16384, "vcpus": 8}

        flavors = [m1_large, m1_tiny, m1_small,  m1_medium, m1_large, m1_xlarge]

        try:
            iflavor = int(flavor)
            flavor = flavors[iflavor]
        except Exception as ex:
            for ele in flavors:
                if ele['name'] == flavor:
                    flavor = ele
                    break

            # default flavor
            flavor = flavors[0]

        return flavor

    def list_networks(self, **params):
        networks = []

        for name in self.conn.listNetworks():
            if "name" in params and params['name'] != name:
                continue

            network = {}
            net = self.conn.networkLookupByName(name)

            #net_id = net.UUIDString()
            net_id = name

            if "id" in params and params['id'] != net_id:
                continue

            status = net.isActive()
            network['id']       =   net_id
            network['name']       =   name
            network['status']   = status

            # get subnets
            net_xml = xml.dom.minidom.parseString(net.XMLDesc(0))
            ip_eles = net_xml.getElementsByTagName('ip')

            subnets = []

            for idx, ip_ele in enumerate(ip_eles):
                subnets.append("%s/%s" % (net.UUIDString(), idx))

            network['subnets']   = subnets
            networks.append(network)

        return {'networks': networks}

    def get_network(self, net):
        networks = self.list_networks(id=net)['networks']

        if len(networks) == 1:
            return {'network': networks[0]}

        networks = self.list_networks(name=net)['networks']

        if len(networks) == 1:
            return {'network': networks[0]}

        return None

    def get_subnet(self, subnet):
        net_id = subnet.split("/")[0]
        subnet_idx = int(subnet.split("/")[1])

        net = self.conn.networkLookupByUUIDString(net_id)
        net_xml = xml.dom.minidom.parseString(net.XMLDesc(0))
        ip_eles = net_xml.getElementsByTagName('ip')

        for idx, ip_ele in enumerate(ip_eles):
            if idx != subnet_idx:
                continue

            net_ip = ip_ele.getAttribute('address')
            net_mask = ip_ele.getAttribute('netmask')
            cidr = IPNetwork("%s/%s" % (net_ip, net_mask))

            return {'subnet': {'cidr': cidr, 'gateway_ip': net_ip}}

    def get_gateway_ip(self, net, ip):
        network = self.get_network(net)['network']

        for subnet_id in network['subnets']:
            subnet = self.get_subnet(subnet_id)['subnet']

            if IPNetwork(subnet['cidr']).__contains__(ip):
                return subnet['gateway_ip']

        return None

    def list_servers(self, **params):
        servers = []

        #for id in self.conn.listDomainsID():
        #for name in self.conn.listDefinedDomains():
        for dom in self.conn.listAllDomains(0):
            server = {}
            name = dom.name()
            #dom = self.conn.lookupByID(int(id))
            server['name'] = name
            # create an anonymous object for server
            servers.append(type('',(object,),server)())

        return servers

    def delete_server(self, server):
        if hasattr(server, 'destroy'):
            server.destroy()
            return

        return

    def _create_vol(self, pool, volname, image, meter=None):
        import urlgrabber.progress as progress
        from virtinst import VirtualDisk

        try:
            from virtinst import StorageVolume
            volname = StorageVolume.find_free_name(pool, volname)
        except:
            from virtinst.Storage import StorageVolume
            volname = StorageVolume.find_free_name(
                    conn=self.conn,
                    pool_object=pool,
                    name=volname)

        size = os.path.getsize(image)

        if hasattr(VirtualDisk, 'build_vol_install'):
            vol_install = VirtualDisk.build_vol_install(self.conn, volname, pool,
                    (float(size) / 1024.0 / 1024.0 / 1024.0), True)
        else:
            from virtinst.VirtualDisk import _build_vol_install

            vol_install = _build_vol_install(volname, pool,
                    (float(size) / 1024.0 / 1024.0 / 1024.0), True)

        vol = vol_install.install()

        # Build stream object
        stream = self.conn.newStream(0)
        def safe_send(data):
            while True:
                ret = stream.send(data)
                if ret == 0 or ret == len(data):
                    break
                data = data[ret:]


        try:
            # Register upload
            offset = 0
            length = size
            flags = 0
            vol.upload(stream, offset, length, flags)

            # Open source file
            fileobj = file(image, "r")

            # Start transfer
            total = 0

            if not meter:
                meter = progress.BaseMeter()

            meter.start(size=size, text="Creating volume %s from %s" % (volname, image))

            while True:
                blocksize = 1024
                data = fileobj.read(blocksize)
                if not data:
                    break

                safe_send(data)
                total += len(data)

                meter.update(total)

            # Cleanup
            stream.finish()
            meter.end(size)
        except:
            if vol:
                vol.delete(0)
            raise

        return vol

    def create_server(self, name=None, image=None, flavor=None, files=None, userdata=None, poll=None, avail_zone=None, net=None, ipaddr=None, volume=None, hints={}):
        import libvirt
        import virtinst
        from virtinst import Guest
        from virtinst import ImportInstaller
        from virtinst import VirtualNetworkInterface
        from virtinst import VirtualDevice
        from virtinst import VirtualDisk
        from virtinst import VirtualGraphics
        from virtinst import support

        import urlgrabber.progress as progress

        if not os.path.exists(image):
            raise MissingImage(image=image)

        typ = 'kvm'

        try:
            #from virtinst import Capabilities
            #print(self.conn.getCapabilities())
            self.conn.caps.guest_lookup('hvm', 'x86_64', typ)
        except Exception as ex:
            typ = 'qemu'

        flavor = self.get_flavor(flavor)

        try:
            installer = ImportInstaller(type=typ, os_type="hvm", conn=self.conn)
            guest = Guest(installer=installer)
            guest.set_name(name)
            guest.set_memory(flavor['mem'])
            guest.set_vcpus(flavor['vcpus'])
            guest.set_autostart(True)
        except Exception as ex:
            installer = ImportInstaller(conn=self.conn)

            guest = self.conn.caps.lookup_virtinst_guest(
                os_type='hvm',
                arch='x86_64',
                typ=typ)
            guest.installer = installer
            guest.name = name
            guest.memory = 1024 * flavor['mem']
            guest.vcpus= flavor['vcpus']
            guest.autostart = True

        guest.replace = True

        # Disks
        disks = []

        vm_home= "%s/.esc/%s" % (os.path.expanduser('~'), name)
        runCmd("mkdir", "-p", vm_home)

        try:
            default_pool = self.conn.storagePoolLookupByName('default')
        except Exception as ex:
            try:
                from virtinst import StoragePool

                StoragePool.build_default_pool(self.conn)
            except:
                import virtinst.cli as cli

                cli.build_default_pool(guest)

            default_pool = self.conn.storagePoolLookupByName('default')

        if not default_pool.isActive():
            default_pool.create()

        vol = self._create_vol(default_pool, name, image, progress.TextMeter())

        # qcow2
        # Copy the image
        '''
        image_name = "%s/%s.qcow2" % (vm_home, name)
        logger.info("Copy image to %s ..." % image_name)
        shutil.copy(image, image_name)

        try:
            dev = VirtualDisk(conn=self.conn, path=image_name)
        except Exception as ex:
            dev = VirtualDisk(conn=self.conn)
            dev.path = image_name
        '''

        if hasattr(VirtualDisk, 'set_vol_object'):
            dev = VirtualDisk(conn=self.conn)
            dev.set_vol_object(vol, default_pool)
        else:
            dev = VirtualDisk(conn=self.conn, volObject=vol)

        dev.format = "qcow2"
        disks.append(dev)

        # create user data
        # Create an ISO file as the datasource for cloud-init to enable ssh password authentication
        user_data_root  = '%s/user_data' % (vm_home)
        user_data_iso   = '%s/user_data.iso' % (vm_home)
        runCmd("mkdir", "-p", user_data_root)

        with open("%s/meta-data" % user_data_root, 'w') as f:
            print("instance-id: %s\nlocal-hostname: %s\n" % (name, name), file=f)

        with open("%s/user-data" % user_data_root, 'w') as f:
            print(userdata, file=f)

        rc, out, err = runCmd("genisoimage", "-output", user_data_iso, "-volid", "cidata", "-joliet", "-rock", "%s/user-data" % user_data_root, "%s/meta-data" % user_data_root)

        '''
        try:
            dev = VirtualDisk(conn=self.conn, path=user_data_iso, device = VirtualDisk.DEVICE_CDROM)
        except Exception as ex:
            dev = VirtualDisk(conn=self.conn)
            dev.path = user_data_iso
            dev.device = VirtualDisk.DEVICE_CDROM
        '''
        vol = self._create_vol(default_pool, "%s.userdata" % name, user_data_iso)

        try:
            dev = VirtualDisk(conn=self.conn, device = VirtualDisk.DEVICE_CDROM, volObject = vol)
        except Exception as ex:
            dev = VirtualDisk(conn=self.conn)
            dev.device = VirtualDisk.DEVICE_CDROM
            dev.set_vol_object(vol, default_pool)

        disks.append(dev)

        # config drive
        meta_files = []

        for k, v in files.iteritems():
            meta_file = {}
            meta_file['path'] = k
            #meta_file['content'] = open(v, 'r').read()
            meta_file['content'] = v
            meta_files.append(meta_file)

        config_drive_root = '%s/config_drive' % (vm_home)
        config_drive_iso = "%s/config_drive.iso" % (vm_home)
        runCmd("mkdir", "-p", user_data_root)

        create_config_drive(config_drive_root, meta_files)
        rc, out, err = runCmd("genisoimage", "-output", config_drive_iso, "-volid", "config-2", "-joliet", "-rock", "%s" % config_drive_root)

        '''
        try:
            dev = VirtualDisk(conn=self.conn, path=config_drive_iso, device = VirtualDisk.DEVICE_CDROM)
        except Exception as ex:
            dev = VirtualDisk(conn=self.conn)
            dev.path = config_drive_iso
            dev.device = VirtualDisk.DEVICE_CDROM
        '''
        vol = self._create_vol(default_pool, "%s.configdrive" % name, config_drive_iso)

        try:
            dev = VirtualDisk(conn=self.conn, device = VirtualDisk.DEVICE_CDROM, volObject = vol)
        except Exception as ex:
            dev = VirtualDisk(conn=self.conn)
            dev.device = VirtualDisk.DEVICE_CDROM
            dev.set_vol_object(vol, default_pool)

        disks.append(dev)

        if hasattr(guest, 'disks'):
            guest.disks.extend(disks)
        else:
            for disk in disks:
                guest.add_device(disk)

        if not guest.get_devices(VirtualDevice.VIRTUAL_DEV_CONSOLE):
            # add default console
            if hasattr(guest, 'add_default_console_device'):
                guest.add_default_console_device()
            else:
                # TODO: Is following code really needed?
                # add console manually
                from virtinst import VirtualCharDevice
                dev = VirtualCharDevice.get_dev_instance(self.conn,
                                                 VirtualCharDevice.DEV_CONSOLE,
                                                 VirtualCharDevice.CHAR_PTY)
                guest.add_device(dev)
        else:
            # for old virtinst(virtinst-0.600), console is installed by default
            pass

        # vnc
        try:
            dev = VirtualGraphics(type='vnc', listen = "127.0.0.1")
        except Exception as ex:
            dev = VirtualGraphics(self.conn)
            dev.type = 'vnc'

        #gdev.set_listen("0.0.0.0")
        guest.add_device(dev)

        for idx, network, ip in enumerateNetIP(net, ipaddr):
            try:
                dev = VirtualNetworkInterface(conn=self.conn,
                                      type=VirtualNetworkInterface.TYPE_VIRTUAL,
                                      network=network)
            except Exception as ex:
                dev = VirtualNetworkInterface(conn=self.conn)
                dev.type = VirtualNetworkInterface.TYPE_VIRTUAL
                dev.source = network
                #print(dev.get_xml_config())

            if ip is not None:
                if hasattr(dev, 'get_macaddr'):
                    macaddr = dev.get_macaddr()
                else:
                    macaddr = dev.macaddr

                xmlstr = '<host mac="%s" name="%s" ip="%s" />' % (macaddr, name, str(ip.ip))

                net = self.conn.networkLookupByName(network)
                cmd = libvirt.VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                #cmd = libvirt.VIR_NETWORK_UPDATE_COMMAND_MODIFY
                section = libvirt.VIR_NETWORK_SECTION_IP_DHCP_HOST
                flags = (libvirt.VIR_NETWORK_UPDATE_AFFECT_LIVE |
                    libvirt.VIR_NETWORK_UPDATE_AFFECT_CONFIG)

                try:
                    net.update(cmd, section, 0, xmlstr, flags)
                except Exception as ex:
                    # Looks like we cannot use libvirt.VIR_NETWORK_UPDATE_COMMAND_MODIFY
                    # to modify an existing host entry
                    net_xml = xml.dom.minidom.parseString(net.XMLDesc(0))
                    for host in net_xml.getElementsByTagName('host'):
                        if host.getAttribute('ip') == str(ip.ip):
                            macaddr = str(host.getAttribute('mac'))

                            if hasattr(dev, 'set_macaddr'):
                                dev.set_macaddr(macaddr)
                            else:
                                dev.macaddr = macaddr

            guest.add_device(dev)
        #final_xml = guest.get_xml_config(install=True, disk_boot=False)
        #print(final_xml)
        domain = guest.start_install()
        #domain = guest.start_install(return_xml = True)
        #print(domain.info())
        return domain

    def _add_static_dhcp(self, net, mac, ip, name=None):
        import libvirt

        if name is None:
            name = "esc-vm"

        xmlstr = '<host mac="%s" name="%s" ip="%s" />' % (mac, name, ip)

        net.update(libvirt.VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST,
            libvirt.VIR_NETWORK_SECTION_IP_DHCP_HOST,
            0, xmlstr,
            libvirt.VIR_NETWORK_UPDATE_AFFECT_CURRENT)

    def create_port(self, net, port_name=None, ip=None):
        from virtinst import VirtualNetworkInterface

        dev = VirtualNetworkInterface(conn=self.conn,
                                  type=VirtualNetworkInterface.TYPE_VIRTUAL,
                                  network=net)
        net = self.conn.networkLookupByName(net)

        if ip is not None:
            if hasattr(dev, 'get_macaddr'):
                macaddr = dev.get_macaddr()
            else:
                macaddr = dev.macaddr

            self._add_static_dhcp(net, macaddr, ip, name=port_name)
            return {'fixed_ips': [{'ip_address': ip}]}
        else:
            net_xml = xml.dom.minidom.parseString(net.XMLDesc(0))
            ip_eles = net_xml.getElementsByTagName('ip')

            for ip_ele in ip_eles:
                for range in net_xml.getElementsByTagName('range'):
                    start = range.getAttribute('start')
                    end = range.getAttribute('end')

                    for ip in IPRange(start, end):
                        try:
                            if hasattr(dev, 'get_macaddr'):
                                macaddr = dev.get_macaddr()
                            else:
                                macaddr = dev.macaddr

                            self._add_static_dhcp(net, macaddr, str(ip), name=port_name)
                            return {'fixed_ips': [{'ip_address': str(ip)}]}
                        except Exception as ex:
                            logger.info(ex)

def create_config_drive(meta_root, meta_files):
    runCmd("mkdir", "-p", "%s/%s" % (meta_root, "/openstack/latest/"))
    runCmd("mkdir", "-p", "%s/%s" % (meta_root, "/openstack/content/"))

    meta_json_files = []

    for meta_file in meta_files:
        path = meta_file['path']
        content_path = '/content/%s' % path
        meta_file_path = '%s/openstack/%s' % (meta_root, content_path)

        with open(meta_file_path, 'w') as f:
            print(meta_file['content'], file=f)

        meta_json_file = {}
        meta_json_file['path'] = path
        meta_json_file['content_path'] = content_path
        meta_json_files.append(meta_json_file)

    meta_json = {}
    meta_json['files'] = meta_json_files

    with open("%s/openstack/latest/meta_data.json" % (meta_root), 'w') as f:
        print(json.dumps(meta_json, sort_keys=True, indent=4), file=f)

class ConfigDrive(object):
    def dump_user_data(self):
        ud = "#cloud-config"
        
        for key in self._user_data:
            ud = "%s\n%s:" % (ud, key)

            values = self._user_data[key]

            if len(values) == 1:
                value = values[0]

                if not value.startswith('-'):
                    ud = "%s %s" % (ud, value)
                else:
                    ud = "%s\n %s" % (ud, value)
            else:
                for value in values:
                    if not value.startswith(' '):
                        ud = "%s\n - %s" % (ud, value)
                    else:
                        ud = "%s\n%s" % (ud, value)

        return ud

    def user_data(self, key, value):
        if not key in self._user_data:
            self._user_data[key] = []

        self._user_data[key].append(value)

    def __init__(self, args):
        self.args = args
        self._user_data = {}

        # if --secure option is used without providing a key with --user_pass. How else can the you ssh into the ESC VM ?
        if args.secure:
            need_user_pass_key=True

            if args.user_pass is not None:
                for user, password, key in self.enumerateUPK(args.user_pass):
                    if key:
                        need_user_pass_key=False

            if need_user_pass_key:
                raise MissingUserPassKey()

        # sanitize_hostname. see rfc952 and rfc1123
        hostname = sanitize_hostname(args.esc_hostname)

        if not hostname == args.esc_hostname:
            logger.warning("Hostname %s doesn't conform to RFC-952 and RFC-1123 specs. Sanitize it to %s." % (args.esc_hostname, hostname))

        self.user_data("hostname", hostname)

        # ssh_pwauth
        if self.args.secure:
            # Disable ssh password authentication
            self.user_data("ssh_pwauth", "False")
        else:
            # Enable SSH password authentication
            self.user_data("ssh_pwauth", "True")

        # bootcmd
        self.user_data("bootcmd",  "[ cloud-init-per, once, bc_idle, sh, -c, \"pwd\"]")

        # This hook is need configure esc_ui job for automatic startup, and kickstart it the first time
        # If esc_ui_startup is false, esc_ui will remain in manual startup configuration
        if self.args.esc_ui_startup:
            self.user_data("bootcmd", "[ cloud-init-per, once, esc_ui_startup, sh, -c, \"$(esc_version -p | awk '{printf $NF}')/esc-scripts/escadm.py ui enable-startup\"]")

        # Disable root login
        self.user_data("bootcmd", "[ cloud-init-per, once, disable_root_login, sh, -c, \"sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config\"]")

        if self.args.secure:
            # Enable iptables:
            self.user_data("bootcmd", "[ cloud-init-per, once, turnon_iptables, sh, -c, \"chkconfig iptables on\"]")
            self.user_data("bootcmd", "[ cloud-init-per, once, turnon_ip6tables, sh, -c, \"chkconfig ip6tables on\"]")
            self.user_data("bootcmd", "[ cloud-init-per, once, copy_iptables, sh, -c, \"cp $(esc_version -p | awk '{printf $NF}')/esc-init/iptables /etc/sysconfig\"]")
            self.user_data("bootcmd", "[ cloud-init-per, once, copy_ip6tables, sh, -c, \"cp $(esc_version -p | awk '{printf $NF}')/esc-init/ip6tables /etc/sysconfig\"]")

            # Re-create host keys for confd
            self.user_data("bootcmd", "[ cloud-init-per, once, confd_ssh_keygen, sh, -c, \"echo y | ssh-keygen -t dsa -f $(esc_version -p | awk '{printf $NF}')/esc_database/confd-keydir/ssh_host_dsa_key -N ''\"]")

            # Re-create keys for confd admin user
            recreate_confd_admin_key = True

            if self.args.user_confd_pass is not None:
                for user, password, key in self.enumerateUPK(self.args.user_confd_pass):
                    if user == 'admin' and key:
                        # should not create the re-create the keys as the public is passed in.
                        recreate_confd_admin_key = False

            if recreate_confd_admin_key:
                self.user_data("runcmd", "[ cloud-init-per, once, confd_keygen_%s, sh, -c, \"/usr/bin/escadm confd keygen --user %s\"]" % ('admin', 'admin'))

            # Turn on selinux
            self.user_data("bootcmd","setenforce 1")

        # write files to ESC VM:
        if self.args.file is not None:
            for fileArg in self.args.file:
                fileArgPair = fileArg.split(':')
                fileOwnership = fileArgPair[0]
                filePermissions = fileArgPair[1]
                filePath = fileArgPair[2]
                fileContents = open(fileArgPair[3], 'r').read()
                self.user_data("write_files", "encoding: b64")
                self.user_data("write_files", "   owner: %s:%s" % (fileOwnership,fileOwnership))
                self.user_data("write_files", "   permissions: '%s'" % (filePermissions))
                self.user_data("write_files", "   path: %s" % filePath)
                self.user_data("write_files", "   content: %s" % base64.b64encode(fileContents.encode('utf-8')).decode("utf-8"))

        # runcmd
        self.user_data("runcmd",  "[ cloud-init-per, once, rc_idle, sh, -c, \"pwd\"]")

        # generate root confd key for backward compatibility 
        self.user_data("runcmd", "[ cloud-init-per, once, confd_keygen_%s, sh, -c, \"/usr/bin/escadm confd keygen --user %s\"]" % ('root', 'root'))

        if self.args.route:
            # The route configuration file is generated after network is up. we need to restart the network to re-configure route.
            self.user_data("runcmd",  "[ cloud-init-per, once, restart_network, sh, -c, \"service network restart\"]")

        if self.args.secure:
            # We need to start iptables/ip6tables manually for the first time.
            self.user_data("runcmd", "[ cloud-init-per, once, start_iptables, sh, -c, \"service iptables start\"]")
            self.user_data("runcmd", "[ cloud-init-per, once, start_ip6tables, sh, -c, \"service ip6tables start\"]")

        # Proxy
        if self.args.proxy is not None:
            for idx, proxy in enumerate(self.args.proxy):
                if "://" not in proxy:
                    proxy = "http://%s"  % proxy

                protocol = proxy[:proxy.find('://')]

                self.user_data("runcmd", "[ cloud-init-per, once, proxy_%d, sh, -c, \"echo export %s_proxy=%s >> /etc/profile.d/proxy.sh\"]" % (idx, protocol, proxy))

        if self.args.noproxy is not None:
                self.user_data("runcmd", "[ cloud-init-per, once, noproxy, sh, -c, \"echo export no_proxy=%s >> /etc/profile.d/proxy.sh\"]" % self.args.noproxy)

        if self.args.runcmd is not None:
            for idx, cmd in enumerate(self.args.runcmd):
                self.user_data("runcmd", "[ cloud-init-per, once, runcmd_%d, sh, -c, \"%s\"]" % (idx, cmd))
        
        # Manage /etc/hosts by cloud-init
        if self.args.etc_hosts_file is None:
            self.user_data("manage_etc_hosts", "true")

    def check_esc_hostname(self):
        for server in vmm.list_servers():
            if server.name == self.args.esc_hostname:
                raise DuplicatedHostName(host=self.args.esc_hostname)

    def build(self, config_drives):
        self.config_drives = config_drives
        return self.args, self.build_esc()

    # build the root element of config drive
    def build_esc(self):
        esc = ET.Element("esc")

        esc.set("version", BOOTVM_VERSION)

        #argv = "%s %s" % (' '.join(sys.argv), self.args)
        argv = ""
        for arg in vars(self.args):
            val = getattr(self.args, arg)

            if val is None:
                continue

            if 'password' in arg or 'encrypt_key' == arg or 'cryptsetup_key' == arg:
                val = '******'
            elif 'user_pass' == arg or 'user_confd_pass' == arg:
                _val = []

                for user, password, key in self.enumerateUPK(val):
                    if key:
                        _val.append("%s:*****:%s" % (user, key))
                    else:
                        _val.append("%s:*****" % user)

                val = _val

            argv = "%s %s" % (argv, "%s=%s" % (arg, val))

        esc.set("argv", base64.b64encode(argv.encode('utf-8')).decode("utf-8"))

        self.build_esc_cloud(esc)
        self.build_esc_service(esc)
        self.build_esc_monitor(esc)

        return esc

    # build the esc-cloud
    def build_esc_cloud(self, esc):
        esc_cloud = ET.SubElement(esc, "esc-cloud")

        self.build_network(esc_cloud)
        self.build_users(esc_cloud)
        self.build_rsyslog_server(esc_cloud)

        #comment it out as we move credentials into DB.
        #self.build_vim_openrc(esc_cloud)

        # Create bootstrap openrc only when booting HA with shared cinder volume
        if self.args.db_volume_id is not None and self.args.ha == 1:
            self.build_bootstrap_openrc(esc_cloud)

        self.build_keepalived(esc_cloud)
        self.build_bgp(esc_cloud)

        self.build_http_rest(esc_cloud)
        self.build_auth(esc_cloud)
        self.build_https_rest(esc_cloud)
        self.build_drbd(esc_cloud)

    def write_hahook_file(self, esc_cloud, nodename, volume_id, disk):
        write_file = ET.SubElement(esc_cloud, "write_file")
        write_file.set("path", "${esc_dir}/esc-scripts/esc_hahook.sh")
        write_file.set("content", "[ ! -f %s ] && source ${esc_dir}/esc-config/openrc.configs/bootstrap_openrc && ${esc_dir}/esc-init/attach_volume.sh %s %s" % (disk, volume_id, nodename))

    def build_drbd(self, esc_cloud):
        if self.args.ha == 2 or self.args.ha == 3:
            drbd = ET.SubElement(esc_cloud, "drbd")

            # we should setup the cluster only on one node. Choose the first one as the initial sync source
            # if self.args.esc_hostname == "%s-0" % (self.args.cluster_name):
            #    drbd.set("initial_sync_source", "true")
            if self.args.db_volume_id is not None:
                '''
                disk = "/dev/disk/by-id/virtio-%s" % (self.args.db_volume_id[:20])
                drbd.set("disk", disk)

                self.write_hahook_file(esc_cloud, args.esc_hostname, args.db_volume_id, disk)
                '''
                drbd.set("disk", '/dev/vdb')
            for i in range(0, len(self.args.ha_node_list)):
                nodename = "%s-%d" % (self.args.ha_name, i)
                drbd_node = ET.SubElement(drbd, "drbdnode")
                drbd_node.set("name", nodename)
                drbd_node.set("port", "%s-port-%s-%d" % (nodename, magicstr, 0))
                drbd_node.set("ip", self.args.ha_node_list[i])

    def build_http_rest(self, esc_cloud):
        http_rest = ET.SubElement(esc_cloud, "http_rest")

        if self.args.enable_http_rest:
            http_rest.set("enabled", "true")
        else:
            http_rest.set("enabled", "false")

    def build_auth(self, esc_cloud):
        auth = ET.SubElement(esc_cloud, "auth")

        if self.args.enable_auth:
            auth.set("enabled", "true")
        else:
            auth.set("enabled", "false")

    def build_https_rest(self, esc_cloud):
        https_rest = ET.SubElement(esc_cloud, "https_rest")

        if self.args.enable_https_rest:
            https_rest.set("enabled", "true")
        else:
            https_rest.set("enabled", "false")

    # We stil need to populate network configuraions through config drive.
    # cloud-init needs 'network_config' config network. It's not always there if 'flat_injected' is not enabled in nova.conf or dhcp is not enabled.
    # even worse, If openstacks use fake IP pool, we cannot have a cloud-init native way to configure network.
    def build_network(self, esc_cloud):
        network = ET.SubElement(esc_cloud, "network")
        network.set("networking", "yes")
        network.set("networking_ipv6", "yes")
        network.set("hostname", self.args.esc_hostname)
        network.set("ipv6_autoconf", "no")
        network.set("nozeroconf", "yes")

        if self.args.gateway_ip != None:
            network.set("gateway", self.args.gateway_ip)

        self.build_interfaces(network)
        self.build_routes(network)

        if self.args.etc_hosts_file != None:
            with open(self.args.etc_hosts_file, 'r') as f:
                for line in f:
                    self.build_hosts(network, "", line.rstrip())

        self.build_resolv(network)
        self.build_ntp_server(network)

    def find_gateway_dev(self, gateway):
        for idx, net, ipaddr in enumerateNetIP(self.args.net, self.args.ipaddr):
            if ipaddr is not None and ipaddr.__contains__(IPAddress(gateway)):
                return "eth" %idx

        return "eth0"

    def build_routes(self, network):
        routes = self.args.route

        if routes is None:
            return

        for route in routes:
            ng_pair = route.split(':')
            net = ng_pair[0]
            gw = ng_pair[1]

            if len(ng_pair) > 2:
                dev = ng_pair[2]
            else:
                dev = self.find_gateway_dev(gw)

            self.user_data("write_files", "content: |")
            self.user_data("write_files", "     %s via %s" % (net, gw))
            self.user_data("write_files", "   path: /etc/sysconfig/network-scripts/route-%s" % (dev))

    def build_ntp_server(self, network):
        ntp_servers = self.args.ntp_server

        if isinstance(ntp_servers, list):
            ntp = ET.SubElement(network, "ntp")
            for idx, ntp_server in enumerate(ntp_servers):
                # should start at 1. See esc-init/esc_network.py
                ntp.set("server%d" % (idx+1), ntp_server)
            ntp.set("timezone", "UTC")

    def build_interfaces(self, network):
        # We should add bgp_anycast_ip to loopback
        bgp_anycast_ip = self.args.bgp_anycast_ip
        if bgp_anycast_ip is not None:
            ipnetwork = IPNetwork(bgp_anycast_ip)

            if not "/" in bgp_anycast_ip:
                if ipnetwork.version == 4:
                    ipnetwork.prefixlen = 24
                else:
                    ipnetwork.prefixlen = 64

            interface = ET.SubElement(network, "interface")
            interface.set("name", "loopback")
            interface.set("onboot", "yes")

            if ipnetwork.version == 4:
                interface.set("device", "lo:2")
                interface.set("ipv6init", "no")
                interface.set("ipaddr", str(ipnetwork.ip))
                interface.set("network", str(ipnetwork.network))
                interface.set("netmask", str(ipnetwork.netmask))
                interface.set("broadcast", str(ipnetwork.broadcast))
            else:
                interface.set("device", "lo")
                interface.set("ipv6init", "yes")
                interface.set("ipv6addr", "%s/%d" % (str(ipnetwork.ip), ipnetwork.prefixlen))
                interface.set("ipaddr", "127.0.0.1")
                interface.set("network", "127.0.0.0")
                interface.set("netmask", "255.0.0.0")
                interface.set("broadcast", "127.255.255.255")

        if self.args.net is None:
            return

        for idx, net in enumerate(self.args.net):
            self.build_interface(network, idx)

    def build_interface(self, network, idx):
        interface = ET.SubElement(network, "interface")
        interface.set("name", "System_eth%d" % (idx))
        interface.set("device", "eth%d" % (idx))
        interface.set("type", "Ethernet")

        # enumerateNetIP only returns once when idx is provided.
        for idx, net, ipaddr in enumerateNetIP(self.args.net, self.args.ipaddr, idx):
            if ipaddr is None:
                interface.set("bootproto", "dhcp")
                break

            ip = str(ipaddr.ip)

            if ipaddr.version == 4:
                interface.set("ipv6init", "no")
                interface.set("ipaddr", ip)
                interface.set("netmask", str(ipaddr.netmask))
            else:
                interface.set("ipv6init", "yes")
                interface.set("ipv6addr", "%s/%d" % (ip, ipaddr.prefixlen))

                # In case of IPV6 gateway, try to determine which interface it belongs to.
                gateway = self.args.gateway_ip

                if isIPV6(gateway):
                    # FIXME: I'm using '__contains__' to do IP range check. If you have any good way, rewrite the following line.
                    if ipaddr.__contains__(IPAddress(gateway)):
                        interface.set("ipv6_defaultgw", gateway)

            interface.set("bootproto", "none")
            self.build_hosts(network, ip, self.args.esc_hostname)

        if idx == self.args.defroute:
            interface.set("defroute", "yes")
        else:
            interface.set("defroute", "no")

        interface.set("nm_controlled", "no")
        interface.set("onboot", "yes")
        interface.set("ipv4_failure_fatal", "yes")

    def build_hosts(self, network, ipaddr, hostname):
        hosts = ET.SubElement(network, "hosts")
        hosts.set("entry", "%s %s" % (ipaddr, hostname))

    def build_resolv(self, network):
        resolv = ET.SubElement(network, "resolv")

        if self.args.domain is not None:
            resolv.set("domain", self.args.domain)

        if self.args.search is not None:
            resolv.set("search", self.args.search)

        nameservers = self.args.nameserver

        if isinstance(nameservers, list):
            for idx, ns in enumerate(nameservers):
                # should start at 1. See esc-init/esc_network.py
                resolv.set("nameserver%d" % (idx+1), ns)

    def build_ntp(self, esc_cloud):
        ntp = ET.SubElement(esc_cloud, "ntp")

    def enumerateUPK(self, user_pass_key):
        if user_pass_key is None:
            return

        p =""
        k = ""

        ssh_key =""

        # both pass and key could be empty
        for upk in user_pass_key:
            upk_triple = upk.split(':')
            u = upk_triple[0]

            if len(upk_triple) >= 2:
                p = upk_triple[1]

            if len(upk_triple) >= 3:
                k = upk_triple[2]

            if u == "":
                raise InvalidUserPassFormat(upk=upk)

            if k != "":
                if not os.path.exists(k):
                    raise MissingUserKey(key=k)
                else:
                    with open(k, 'r') as ssh_key_file:
                        ssh_key = ssh_key_file.read()

            yield u, p, ssh_key

    def build_users(self, esc_cloud):
        user_confd_pass = []

        if self.args.user_confd_pass is not None:
            user_confd_pass.extend(self.args.user_confd_pass)

        for user, password, key in self.enumerateUPK(user_confd_pass):
            hashPassword = ""

            # determine format of password
            if password[:1] == '$' and password[1:2].isdigit() and password[2:3] == '$':
                hashPassword = password
            else:
                if password != "":
                    # encrypt clear text password
                    randomSalt = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(4))

                    # TODO: does crypt.crypt always return as expected?
                    # On python 2.7: python -c 'import crypt; print crypt.crypt("password", "$6$saltsalt$")'
                    # returns: $6FMi11BJFsAc
                    # On python 2.6, it returns:
                    # $6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/

                    hashPassword = crypt.crypt(password, '$6$' + randomSalt)

            if not hashPassword and not key:
                continue

            user_confd = ET.SubElement(esc_cloud, 'user_confd')
            user_confd.set('name', user)

            if hashPassword != "":
                user_confd.set('password_hash', hashPassword)

            if key != "":
                user_confd.set('key', base64.b64encode(key))

        # user data

        # Disable root login
        if self.args.secure:
            self.user_data("users", "name: root")
            self.user_data("users", "   lock-passwd: true")

        user_pass = []

        if self.args.user_pass is not None:
            user_pass.extend(self.args.user_pass)

        # default username and password
        add_default_admin = True

        for user, password, key in self.enumerateUPK(user_pass):
            if user == 'admin':
                add_default_admin = False
                break

        if add_default_admin:
            user_pass.extend(['admin:cisco123'])

        self.user_data("runcmd", "[ cloud-init-per, once, var_confd_homes_ssh_mkdir, sh, -c, \"mkdir -p /var/confd/homes/admin/.ssh/\"]")

        for user, password, key in self.enumerateUPK(user_pass):
            self.user_data("users", "name: %s" % user)
            self.user_data("users", "   gecos: %s" % "User created by cloud-init")

            # determine format of password
            if password[:1] == '$' and password[1:2].isdigit() and password[2:3] == '$':
                hashPassword = password
            else:
                # TODO: Should it better to use sha512 hashed password?
                hashPassword = crypt.crypt(password, 'xy')

            if password != "":
                self.user_data("users", "   passwd: %s" % hashPassword)
                self.user_data("users", "   lock-passwd: false")

            if key != "":
                self.user_data("users", "   ssh-authorized-keys:")
                self.user_data("users", "     - %s" % key)

            self.user_data("users", "   homedir: /home/%s" % (user))

            # All users with name other than 'admin' are 'non-admin' users.
            if user == 'admin':
                self.user_data("users", "   sudo: ALL=(ALL) ALL")
        
            self.user_data("runcmd", "[ cloud-init-per, once, confd_keygen_%s, sh, -c, \"/usr/bin/escadm confd keygen --user %s\"]" % (user, user))

        # We need to change the owner to tomcat as who confd is running.
        self.user_data("runcmd", "[ cloud-init-per, once, var_confd_homes_chown, sh, -c, \"chown -R tomcat:tomcat /var/confd/homes/admin/\"]")

    def build_keepalived(self, esc_cloud):
        if not self.args.ha:
            return

        keepalived = ET.SubElement(esc_cloud, "keepalived")

        notification_email = self.args.kad_notification_email
        if notification_email is not None:
            notification_email_from = self.args.kad_notification_email_from

            if notification_email_from is None:
                notification_email_from = "root@%s" % self.args.esc_hostname

            keepalived.set("notification_email_from", notification_email_from)
            keepalived.set("smtp_server", self.args.kad_smtp_server)
            keepalived.set("notification_email", notification_email)

        keepalived.set("router_id", "esc@vsoc-kd-u01")
        keepalived.set("priority", "101")
        keepalived.set("auth_pass", "cisco123")

        if self.args.kad_vip is not None:
            keepalived.set("virtual_ipaddress", self.args.kad_vip)

        keepalived.set("interface", self.args.kad_vif)

        vri = self.args.kad_vri
        if vri is not None:
            keepalived.set("virtual_router_id", vri)

        if self.args.kad_unicast_src_ip:
            keepalived.set("unicast_src_ip", self.args.kad_unicast_src_ip)

        if self.args.kad_unicast_peer:
            unicast_peer = ""

            for peer in self.args.kad_unicast_peer:
                unicast_peer = "%s %s" % (unicast_peer, peer)

            keepalived.set("unicast_peer", unicast_peer)

    def build_rsyslog_server(self, esc_cloud):
        logserver = self.args.rsyslog_server
        logserverport = self.args.rsyslog_server_port
        logserverprotocol = self.args.rsyslog_server_protocol
        if logserver is not None:
            if logserverprotocol is not None and len(logserverprotocol.strip()) > 0:
                if logserverprotocol.lower()=='tcp':
                    protocolspecifier = '@@'
                else:
                    protocolspecifier = '@'
            if logserverport is not None and len(logserverport.strip()) > 0:
                if not logserverport.isdigit():
                    logserverport = '514'

            self.user_data("rsyslog", "- \"*.* %s[%s]:%s\"" % (protocolspecifier, logserver, logserverport))

            return

            rsyslog = ET.SubElement(esc_cloud, "rsyslog")
            rsyslog.set("logserver", logserver)
            rsyslog.set("logserverport", logserverport)
            rsyslog.set("logserverprotocol", logserverprotocol)

    # openrc used by esc manager
    def build_vim_openrc(self, esc_cloud):
        openrc = ET.SubElement(esc_cloud, "vim_openrc")
        openrc.set("os_tenant_name", self.args.os_tenant_name)
        openrc.set("os_username", self.args.os_username)
        openrc.set("os_password", self.args.os_password)
        openrc.set("os_auth_url", self.args.os_auth_url)

    # openrc of openstack to bootstrap ESC VM
    def build_bootstrap_openrc(self, esc_cloud):
        openrc = ET.SubElement(esc_cloud, "bootstrap_openrc")
        openrc.set("os_tenant_name", self.args.bs_os_tenant_name)
        openrc.set("os_username", self.args.bs_os_username)
        openrc.set("os_password", self.args.bs_os_password)
        openrc.set("os_auth_url", self.args.bs_os_auth_url)

    # build the esc-service
    def build_esc_service(self, esc):
        esc_service = ET.SubElement(esc, "esc-service")

        self.build_disk(esc_service)
        self.build_service_inits(esc_service)
        self.build_cluster(esc_service)

    # build cluster
    def build_cluster(self, esc_service):
        if not self.args.cluster:
            return

        if self.args.ha:
            return

        clustername = self.args.cluster_name
        localnode = self.args.esc_hostname

        cluster = ET.SubElement(esc_service, "cluster")
        cluster.set("name", clustername)
        cluster.set("localnode", localnode)

        if self.args.vip is not None:
            cluster.set("vip", self.args.vip)

        # we should setup the cluster only on one node. Choose the first one
        if localnode == "%s-0" % (clustername):
            cluster.set("setup", "true")

        for i in range(0, self.args.cluster):
            nodename = "%s-%d" % (self.args.cluster_name, i)
            clusternode = ET.SubElement(cluster, "clusternode")
            clusternode.set("name", nodename)

            # Use the first port.
            clusternode.set("port", "%s-port-%s-%d" % (nodename, magicstr, 0))

    def build_disk(self, esc_service):
        volume_id = self.args.db_volume_id

        # Validate the volume
        '''
        if volume_id is not None:
            cinder = cinderclient.Client('1', *vmm.getBootstrapOpenStackCredentials())

            try:
                volume = cinder.volumes.get(volume_id)
            except Exception as ex:
                logger.error("Cannot retrieve volume: %s" % (volume_id))
                logger.exception("Exception while retrieving volume")
                exit(1)

            if not volume.status == 'in-use' and not volume.status == 'available':
                logger.error("You cannot use the volume in '%s' status" % (volume.status))
                exit(1)
        '''

        # we support 4 user cases:
        # 0, database volume in standalone ESC
        # 1, shared database volume in HA
        # 2, DRBD in HA
        # 3, volume + DRBD in HA

        disk = ET.SubElement(esc_service, "disk")

        # TODO: script needs cleanup
        if self.args.ha == 2:
            # case 2
            #disk.set("device", "/dev/drbd/by-res/esc")
            disk.set("device", "/dev/drbd1")
            disk.set("type", "ext4")
            disk.set("mount_point", "${esc_dir}/esc_database")
        elif self.args.ha == 3:
            # case 3
            disk.set("type", "ext4")
            disk.set("mount_point", "${esc_dir}/esc_database")
            disk.set("device", "/dev/drbd1")
        elif self.args.ha == 1:
            # case 1
            disk.set("volume_id", volume_id)
            disk.set("type", "ext4")
            disk.set("mount_point", "${esc_dir}/esc_database")
            disk.set("device", "/dev/vdb1")
        else:
            # case 0
            if volume_id is None:
                # Delete useless disk element.
                esc_service.remove(disk)
                return

            disk.set("volume_id", volume_id)
            disk.set("type", "ext4")
            disk.set("mount_point", "${esc_dir}/esc_database")
            disk.set("device", "/dev/vdb1")

    def build_service_inits(self, esc_service):
        service_init = ET.SubElement(esc_service, "service-init")

        # Comment out ppm/pa
        #self.build_application(service_init, "pa", "service trucq start")
        #self.build_application(service_init, "ppm.gw", "service ppm.gw start")
        #self.build_application(service_init, "esc_confd", "service esc_confd start")
        #self.build_application(service_init, "escbe_statd", "service escbe_statd start")
        #self.build_application(service_init, "esc_listener", "service esc_listener start")

    def build_bgp(self, esc_cloud):
        if self.args.bgp_local_ip == None:
            return

        bgp = ET.SubElement(esc_cloud, "bgp")

        bgp.set("local_ip", self.args.bgp_local_ip)
        bgp.set("anycast_ip", self.args.bgp_anycast_ip)
        bgp.set("remote_ip", self.args.bgp_remote_ip)
        bgp.set("local_as", self.args.bgp_local_as)
        bgp.set("remote_as", self.args.bgp_remote_as)
        bgp.set("local_router_id", self.args.bgp_local_router_id)

        if self.args.bgp_md5 is not None:
            bgp.set("md5", self.args.bgp_md5)
        else:
            bgp.set("md5", "None")

    def build_application(self, service_init, name, command):
        application = ET.SubElement(service_init, "application")
        application.set("name", name)
        application.set("command", command)

    # build the esc-monitor
    def build_esc_monitor(self, esc):
        esc_monitor = ET.SubElement(esc, "esc-monitor")
        self.build_statusreporter(esc_monitor)
        self.build_watchdog(esc_monitor)

    def build_statusreporter(self, esc_monitor):
        statusreporter = ET.SubElement(esc_monitor, "statusreporter")
        self.build_statusreporter_config(statusreporter)

    def build_statusreporter_config(self, statusreporter):
        config = ET.SubElement(statusreporter, "config")

        if self.args.esc_monitor_check_ips != None:
            network = ET.SubElement(config, "network")
            check_ips = ET.SubElement(network, "check_ips")
            check_ips.text = ",".join(self.args.esc_monitor_check_ips)

    def build_watchdog(self, esc_monitor):
        watchdog = ET.SubElement(esc_monitor, "watchdog")
        port =  ET.SubElement(watchdog, "port")
        port.text = "60000"

        self.build_watchdog_rules(watchdog)

    def build_watchdog_rules(self, watchdog):
        self.build_watchdog_exception_rule(watchdog)
        self.build_watchdog_error_rule(watchdog)
        self.build_watchdog_deadlock_rule(watchdog)
        self.build_watchdog_openstack_rule(watchdog)

    def build_watchdog_error_rule(self, watchdog):
        rule = ET.SubElement(watchdog, "rule")
        _type = ET.SubElement(rule, "type")
        _type.text = 'error'
        action = ET.SubElement(rule, "action")
        action.text = 'LOG'


    def build_watchdog_deadlock_rule(self, watchdog):
        rule = ET.SubElement(watchdog, "rule")
        _type = ET.SubElement(rule, "type")
        _type.text = 'deadlock'
        action = ET.SubElement(rule, "action")
        action.text = 'LOG'
        action = ET.SubElement(rule, "interval")
        action.text = '60'

    def build_watchdog_exception_rule(self, watchdog):
        rule = ET.SubElement(watchdog, "rule")
        _type = ET.SubElement(rule, "type")
        _type.text = 'exception'
        regex = ET.SubElement(rule, "regex")
        regex.text = 'Exception'
        action = ET.SubElement(rule, "action")
        action.text = 'LOG'

    def build_watchdog_openstack_rule(self, watchdog):
        rule = ET.SubElement(watchdog, "rule")
        _type = ET.SubElement(rule, "type")
        _type.text = 'openstack'
        tenant= ET.SubElement(rule, "tenant")
        tenant.text = self.args.os_tenant_name
        interval= ET.SubElement(rule, "interval")
        interval.text = '60'
        actions = ET.SubElement(rule, "actions")
        actions.text = 'NOTIFY_CONFD_ESC_OUT_OF_SERVICE'
        actions = ET.SubElement(rule, "actions")
        actions.text = 'WAIT_FOR_OPENSTACK'
        actions = ET.SubElement(rule, "actions")
        actions.text = 'NOTIFY_CONFD_ESC_IN_SERVICE'

    def compute_net_id(self):
        args = self.args
        net_ids = []

        for net in args.net:
            networks = vmm.list_networks(fields="id", id=net)['networks']

            if len(networks) == 0:
                networks = vmm.list_networks(fields="id", name=net)['networks']

            if len(networks) == 0:
                raise InvalidateNetwork(net=net)

            elif len(networks) != 1:
                raise MultipleNetwork(net=net)
            else:
                net_id = networks[0]['id']
                net_ids.append(net_id)

        args.net = net_ids

def runCmd(*args):
    if type(args[0]) == list:
        argList = args[0]
    else:
        argList=args

    if argList[0] == "-c":
        p = subprocess.Popen(argList, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    else:
        p = subprocess.Popen(argList, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out, err = p.communicate()
    rc = p.returncode

    return rc, out.decode('ascii'), err.decode('ascii')


class GetNetIdError(Exception):
    def __init__(self, msg):
        self.msg = msg

class SplitAppendAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        existing_values = getattr(namespace, self.dest)

        if existing_values is None:
            existing_values = []

        if values is not None:
            for value in re.split('[;, ]+',  ' '.join(values)):
                existing_values.append(value)

        setattr(namespace, self.dest, existing_values)

class ExtendAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        existing_values = getattr(namespace, self.dest)

        if existing_values is None:
            existing_values = []

        if values is not None:
            existing_values.extend(values)

        setattr(namespace, self.dest, existing_values)

class AppendIpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        ipaddrs = getattr(namespace, self.dest)

        if ipaddrs is None:
            ipaddrs = []

        for ipaddr in values:
            if ipaddr is None or ipaddr.lower() == 'dhcp' or ipaddr.lower() == 'none':
                ipaddrs.append(None)
            else:
                ipaddrs.append(ipaddr)

        setattr(namespace, self.dest, ipaddrs)

class EncryptKeyPromptAction(argparse.Action):
    def __init__(self,
                 option_strings,
                 dest=argparse.SUPPRESS,
                 default=None,
                 help=None):
        super(EncryptKeyPromptAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs='?',
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        if values is None:
            while True:
                key = getpass.getpass("Please type the encryption key:")
                key2 = getpass.getpass("Please re-type the encryption key:")

                if key == key2:
                    break

                print("Encryption key does not match. Please try again")
        else:
            key = values

        setattr(namespace, self.dest, key)

class TestAction(argparse.Action):
    def __init__(self,
                 option_strings,
                 dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS,
                 help=None):
        super(TestAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        global vmm, vmm_vnf

        args = namespace

        if args.image is None:
            print("In order to run self-test, you at least need to specify the image.")
            parser.exit()

        argv = ['./bootvm.py']

        if args.libvirt is not None:
            argv.append('--libvirt')
            vmm = LibVirtManager(args)
            net = 'default'
        else:
            vmm = OSManager(args)
            net = 'esc-net'

        vmm_vnf = OSManager(args)

        # test case 1,
        #test(args.image, argv, net=net)

        # test case 2,
        # HA
        # drbd
        #test(args.image, argv, ha="drbd", net=net)

        # shared cinder volume
        if args.libvirt is None:
            test(args.image, argv, ha="cinder", net=net)

        # drbd_on_cinder
        if args.libvirt is None:
            test(args.image, argv, ha="drbd_on_cinder", net=net)
        #    test case 2,

        parser.exit()

def build_security_group_rules():
    security_group_rules = []
    security_group_rules.append(build_security_group_rule(-1, "icmp", -1))
    security_group_rules.append(build_security_group_rule(-1, "icmp", -1, cidr="::0/0"))
    security_group_rules.append(build_security_group_rule(161, "udp", 161))
    security_group_rules.append(build_security_group_rule(22, "tcp", 22))
    security_group_rules.append(build_security_group_rule(23, "tcp", 23))

    return {"security_group_rules": security_group_rules}

def build_security_group_rule(from_port, ip_protocol, to_port, cidr="0.0.0.0/0"):
    security_group_rule = {}
    security_group_rule['from_port'] = from_port
    security_group_rule['ip_protocol'] = ip_protocol
    security_group_rule['to_port'] = to_port
    security_group_rule['cidr'] = cidr

    return security_group_rule

def isIPV4(ipaddr):
    try:
        ipnetwork = IPNetwork(ipaddr)
        socket.inet_aton(str(ipnetwork.ip))
    except:
        return False

    return True

def isIPV6(ipaddr):
    try:
        ipnetwork = IPNetwork(ipaddr)
        socket.inet_pton(socket.AF_INET6, str(ipnetwork.ip))
    except:
        return False

    return True

# Here, I call the argument like 'net2_id' as an indexed argument.
# Given regexpr: 'net([0-9]*)_id', arg: 'net2_id=esc-net', args:[]
# Calling map_indexed_arg() results in args:[None, 'esc-net']
def map_indexed_arg(regexpr, arg, args):
    m = re.search(regexpr, arg)

    if m is None:
        return False

    if m.group(1) == '':
        idx = 1
    else:
        idx = int(m.group(1))

    args += [None] * (idx - len(args))

    kvpair = arg.split('=')
    value = kvpair[1]

    args[idx-1] = value

    return True

def esc_ui_startup(value):
    if value.lower()  == 'yes' or value.lower() == 'true' or value == '1':
        return True

    if value.lower()  == 'no' or value.lower() == 'false' or value == '0':
        return False

    logger.warning("Invalid parameter for esc_ui_startup, %s, defaulted to True" % (value))
    logger.warning("      Valid choice: { yes | true | 1 | no | false | 0 }")

    return True

def precreate_kad_vip(args):
    net_idx = int(args.kad_vif.strip('eth'))
    net = args.net[net_idx]
    port_name = "%s-port-%s-VIP" % (args.esc_hostname, magicstr)
    port = vmm.create_port(net, port_name)

    kad_vip = port['fixed_ips'][0]['ip_address']
    logger.info("The kad virtual ipaddress is created automatically: %s" % (kad_vip))

    return kad_vip

def check_ha_mode(value):
    try:
        ivalue = int(value)
    except Exception as ex:
        try:
            ivalue = ['no_ha', 'cinder', 'drbd', 'drbd_on_cinder'].index(value)
        except Exception as ex:
            raise InvalidHaMode(ha_mode=value)

    if ivalue < 0 or ivalue > 3:
        raise InvalidHaMode(ha_mode=ivalue)

    return ivalue

def enumerateNetIP(nets, ipaddrs, index=-1):
    if nets is None:
        return

    for idx, net in enumerate(nets):
        if ipaddrs is None:
            ipaddr = None
        else:
            ipaddr = ipaddrs[idx] if len(ipaddrs) > idx else None

        ipnetwork = None

        if ipaddr is not None:
            ipnetwork = IPNetwork(ipaddr)

            if not "/" in ipaddr:
                if ipnetwork.version == 4:
                    ipnetwork.prefixlen = 24
                else:
                    ipnetwork.prefixlen = 64

            # Try network name
            networks = vmm.list_networks(fields="subnets", name=net)['networks']

            if len(networks) == 0:
                # Try network id
                networks = vmm.list_networks(fields="subnets", id=net)['networks']

            for subnet_id in networks[0]['subnets']:
                subnet = IPNetwork(vmm.get_subnet(subnet_id)['subnet']['cidr'])
                if subnet.__contains__(ipnetwork.ip):
                    # The subnet range contains the ip. Use the prefixlen defined.
                    if not ipnetwork.prefixlen == subnet.prefixlen:
                        #logger.warning("The prefixlen doesn't match the one defined in subnet. Use /%d instead of /%d." % (subnet.prefixlen, ipnetwork.prefixlen))
                        ipnetwork.prefixlen = subnet.prefixlen
                    break

        if index == -1:
            yield idx, net, ipnetwork
        else:
            if index == idx:
                yield idx, net, ipnetwork
            else:
                continue

def test(image, argv, ha=None, net=None):
    argv = copy.deepcopy(argv)
    test_net = net
    random_str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    esc_hostname = 'esc-%s' % random_str
    test_tenant_name = 'tenant-%s' % random_str
    argv.extend(['--runcmd', "while true ; do sleep 10; health.sh || continue; service esc_confd status || continue; netstat -lnt | grep :830 -q || continue; sleep 15; /opt/cisco/esc/esc-confd/esc-cli/esc_nc_cli create-tenant %s; break; done 2>&1 | tee /tmp/abc &" % test_tenant_name])
    argv.extend(['--net', test_net])
    argv.extend(['--image', image])

    if ha is None:
        argv.extend([esc_hostname])
        servers = tmain(argv)
    elif ha == "cinder":
        port_vip = vmm.create_port(test_net, "%s-port-vip-1" % (esc_hostname))
        kad_vip = port_vip['fixed_ips'][0]['ip_address']
        argv.extend(['--ha_mode', ha, '--kad_vip', kad_vip])
        argv.extend([esc_hostname])
        servers = tmain(argv)
    else:
        port0 = vmm.create_port(test_net, "%s-port-0" % (esc_hostname))
        port1 = vmm.create_port(test_net, "%s-port-1" % (esc_hostname))
        ipaddr0 = port0['fixed_ips'][0]['ip_address']
        ipaddr1 = port1['fixed_ips'][0]['ip_address']
        gateway0 = vmm.get_gateway_ip(test_net, ipaddr0)
        gateway1 = vmm.get_gateway_ip(test_net, ipaddr1)
        ha_node_list = '%s,%s' % (ipaddr0, ipaddr1)

        if ha == "drbd":
            pass
        else: # drbd_on_cinder
            pass

        port_vip = vmm.create_port(test_net, "%s-port-vip-1" % (esc_hostname))
        kad_vip = port_vip['fixed_ips'][0]['ip_address']
        servers0 = tmain(argv + ['--ha_mode', ha, '--ipaddr', ipaddr0, '--gateway_ip', gateway0, '--ha_node_list', ha_node_list, '--kad_vip', kad_vip, "%s-0" % (esc_hostname)])
        servers1 = tmain(argv + ['--ha_mode', ha, '--ipaddr', ipaddr1, '--gateway_ip', gateway1, '--ha_node_list', ha_node_list, '--kad_vip', kad_vip, "%s-1" % (esc_hostname)])
        servers = servers0 + servers1
    # check if the test tenant is created
    timeout=240
    while True:
        logger.info("Wait for the test tenant %s to be created ..." % test_tenant_name)
        tenant = vmm_vnf.get_tenant(test_tenant_name)

        if tenant is not None:
            logger.info("Passed")

            for server in servers:
                vmm.delete_server(server)

            tenant.delete()
            break

        if timeout < 0:
            logger.info("Failed: %s" % argv)
            break

        timeout = timeout - 5
        time.sleep(30)

def tmain(argv):
    logger.info("Test: %s" % argv)
    return main(argv)

class JsonFormatter(logging.Formatter):
    def formatException(self, exc_info):
        """
        Format an exception so that it prints on a single line.
        """
        result = super(JsonFormatter, self).formatException(exc_info)
        return repr(result) # or format into one line however you want to

    def format(self, record):
        ret = {"status": "Success"}

        if isinstance(record.msg, dict):
            # user is providing the dictionary. do not format it.
            ret.update(record.msg)
        else:
            s = super(JsonFormatter, self).format(record)

            if record.exc_text:
                s = s.replace('\n', '') + '|'
                ret.update({"status": "Failure"})
            else:
                ret.update({"status": "Success"})

            # For simplicity, return the error message without the whole trace back.
            s = record.getMessage()
            ret.update({"message": s})

        return json.dumps(ret, sort_keys=True, indent=4)

'''
    Support only emit the last record.
'''
class BootVMStreamHandler(logging.StreamHandler):
    def __init__(self, stream=None):
        self.last_record = None
        self.emit_last = False

        super(BootVMStreamHandler, self).__init__(stream)

    def emit(self, record):
        if not self.emit_last:
            super(BootVMStreamHandler, self).emit(record)
        else:
            self.last_record = record

    def emitLast(self):
        self.emit_last = True

    def close(self):
        if self.emit_last:
            self.emit_last = False

            if self.last_record:
                self.emit(self.last_record)

        super(BootVMStreamHandler, self).close()

def main(argv):
    global vmm, vmm_vnf
    global logger
    global magicstr

    servers = []

    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.DEBUG)
    rootLogger.propagate = 0

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    stdoutLogHandler = BootVMStreamHandler(sys.stdout)
    stdoutLogFormatter = logging.Formatter('%(message)s', None)
    stdoutLogHandler.setFormatter(stdoutLogFormatter)
    stdoutLogHandler.setLevel(logging.INFO)

    logger.addHandler(stdoutLogHandler)

    # A magic random string. Right now I'm using it to generate port names.
    magicstr = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

    try:
        parser = argparse.ArgumentParser(description='Boot ESC VM into an openstack.', add_help=True)

        parser.add_argument("--test", action=TestAction, help="Run self tests.")

        # dryrun option
        parser.add_argument("--dryrun", default=False, action='store_true', help="display only, do not execute")

        # version
        parser.add_argument("--version", default=False, action='store_true', help="Print bootvm.py version and exit")

        # poll option to block and display status while booting
        parser.add_argument("--poll", default=False, action='store_true', help="Blocks while instance builds so progress can be reported")

        # esc host name
        parser.add_argument("esc_hostname", help="Host name for the new ESC VM.")

        # secure configuration
        #   disable ssh password authentication
        #   disable root login
        #   generate new SSH host keys of confd
        #   selinux in enforceing mode
        #   enable iptables/ip6tables
        parser.add_argument("--secure", default=False, action='store_true', help="Enable secure configuration for ESC VM.")

        # OpenStack credentials used to bootstrap ESC VM
        # default value is read from environment
        bs_os_group = parser.add_argument_group('Arguments of openstack where to bootstrap ESC VM')
        bs_os_group.add_argument("--bs_os_auth_url", default=os.environ.get('OS_AUTH_URL'), help="Defaults to env[OS_AUTH_URL].")
        bs_os_group.add_argument("--bs_os_tenant_name", default=os.environ.get('OS_TENANT_NAME'), help="Defaults to env[OS_TENANT_NAME].")
        bs_os_group.add_argument("--bs_os_username", default=os.environ.get('OS_USERNAME'), help="Defaults to env[OS_USERNAME].")
        bs_os_group.add_argument("--bs_os_password", default=os.environ.get('OS_PASSWORD'), help="Defaults to env[OS_PASSWORD].")

        # Credentials of OpenStack that ESC Manager works with
        # default values are assigned from bootstrap values,e.g. os_auth_url = bs_os_auth_url
        os_group = parser.add_argument_group('Arguments of openstack that ESC manager works with')
        os_group.add_argument("--os_auth_url", default=os.environ.get('OS_AUTH_URL'), help="Defaults to env[OS_AUTH_URL].")
        os_group.add_argument("--os_tenant_name", default=os.environ.get('OS_TENANT_NAME'), help="Defaults to env[OS_TENANT_NAME].")
        os_group.add_argument("--os_username", default=os.environ.get('OS_USERNAME'), help="Defaults to env[OS_USERNAME].")
        os_group.add_argument("--os_password", default=os.environ.get('OS_PASSWORD'), help="Defaults to env[OS_PASSWORD].")

        parser.add_argument("--no_vim_credentials", default=False, action='store_true', help="Don't pass vim credentials and you have to configure those credentials after installation." )

        # support to boot ESC via libvirt
        parser.add_argument("--libvirt", nargs='?', const="qemu:///system", help="Boot ESC via libvirt")

        # HA. By default, HA is disabled. depeciated, use '--cluster' instead
        ha_group = parser.add_argument_group('ha arguments')
        ha_group.add_argument("--ha_mode", type=check_ha_mode, action='store', dest='ha', help="Define the HA mode. no_ha: No HA, cinder: Shared Cinder Volume, drbd: Built-in DRBD, drbd_on_cinder: DRBD over Cinder Volume")

        # Cluster
        cluster_group = parser.add_argument_group('cluster arguments')
        cluster_group.add_argument("--cluster", type=int, nargs='?', const=2, help="Enable cluster.")
        cluster_group.add_argument("--vip", help="virtual ipaddress of esc cluster")

        # keepalived
        ha_group.add_argument("--kad_vip", help="virtual ipaddress of vrrp instance")
        ha_group.add_argument("--kad_vif", default='eth0', help="interface of vrrp instance")
        ha_group.add_argument("--kad_vri", help="virtual router id of vrrp instance. Use the last byte of vip if it's not specified, ")
        ha_group.add_argument("--kad_unicast_src_ip", help="Set the source IP address of unicast")
        ha_group.add_argument("--kad_unicast_peer", nargs='*', action=ExtendAction, help="Set the peer IP addresses of unicast")

        # email notification for keepavlied
        ha_group.add_argument("--kad_notification_email_from", help="notification_email_from")
        ha_group.add_argument("--kad_smtp_server", default="127.0.0.1", help="smtp_server")
        ha_group.add_argument("--kad_notification_email", help="notification_email")

        # bgp
        ha_group.add_argument("--bgp_local_ip", help="bgp_local_ip")
        ha_group.add_argument("--bgp_anycast_ip", help="bgp_anycast_ip")
        ha_group.add_argument("--bgp_remote_ip", help="bgp_remote_ip")
        ha_group.add_argument("--bgp_local_as", help="bgp_local_as")
        ha_group.add_argument("--bgp_remote_as", help="bgp_remote_as")
        ha_group.add_argument("--bgp_local_router_id", help="bgp_local_router_id")
        ha_group.add_argument("--bgp_md5", help="bgp_md5")

        # Network
        nw_group = parser.add_argument_group('network arguments')
        nw_group.add_argument("--net", default=[], nargs='*', action=ExtendAction, help="On the ESC VM, create a NIC attached to network with this ID or name.")
        nw_group.add_argument("--ipaddr", nargs='*', action=AppendIpAction, help="Boot the ESC VM with this static ip.")
        nw_group.add_argument("--peer_ipaddr", nargs='*', action=AppendIpAction, help="Specify the ip address of the peer node while deplying HA if want to deploy two nodes at one time.")
        nw_group.add_argument("--ha_node_list", nargs='*', action=SplitAppendAction, help="Specify the ip addresses of nodes while deplying HA.")
        nw_group.add_argument("--gateway_ip", nargs='?', help="Define the gateway ip.")
        nw_group.add_argument("--defroute", type=int, default=0, help="Specify which interface is the default route.")
        nw_group.add_argument("--domain", help="Domain")
        nw_group.add_argument("--search", help="Search")
        nw_group.add_argument("--nameserver", nargs='*', action=ExtendAction, help="Nameservers")
        nw_group.add_argument("--ntp_server", nargs='*', action=ExtendAction, help="Ntp server")
        nw_group.add_argument("--route", nargs='*', action=AppendIpAction, help="Specify static route.")

        #
        parser.add_argument("--rsyslog_server", help="Specify the server of rsyslogd")
        parser.add_argument("--rsyslog_server_port", default="514", help="Specify the server port of rsyslogd")
        parser.add_argument("--rsyslog_server_protocol", default="udp", help="Specify the server protocol of rsyslogd (TCP/UDP)")

        #
        parser.add_argument("--image", required=True, help="Boot the ESC VM with this image ID or name.")
        parser.add_argument("--hint",  nargs='*', metavar='<key=value>', action=ExtendAction, help="Specify OpenStack hints.")
        parser.add_argument("--avail_zone", default=None, help="The availability zone for ESC VM placement.")
        parser.add_argument("--flavor", default="m1.large", help="Name or ID of flavor.")
        parser.add_argument("--db_volume_id", help="The database volume attached to ESC VM.")

        #
        parser.add_argument("--security_rules_file", help="security_rules_file")
        parser.add_argument("--esc_params_file", help="esc_params_file")
        parser.add_argument("--host_mapping_file", help="host_mapping_file")
        parser.add_argument("--etc_hosts_file", help="etc_hosts_file")
        parser.add_argument("--user_pass", nargs='*', action=ExtendAction, help="Add a user for access to esc vm. Format user_name:password[:key]\nThis option can be repeated\nWithout this argument, default user is added admin:cisco123\nWith this argument, default user is not added")
        parser.add_argument("--user_confd_pass", nargs='*', action=ExtendAction, help="Add or modify a confd users. Format user_name:password\nThis option can be repeated\nWithout this argument, default user_confd is added admin:admin\nWith this argument, default user_confd is not added")

        #
        parser.add_argument("--esc_ui_startup", default=True, type=esc_ui_startup, help="Control automatic startup of ESC UI.  If disabled with false|no, esc_ui process can be started manually on ESC VM after instalation.")

        # Proxy
        parser.add_argument("--proxy", nargs='*', action=ExtendAction, help="Use proxy on given port. Syntax: [PROTOCOL://][USERNAME:PASSWORD@]HOST[:PORT]")
        parser.add_argument("--noproxy", nargs='?', help="List of hosts which do not use proxy")

        # create files
        parser.add_argument("--file", nargs='*', action=ExtendAction, help="Create a file on VM as owner:permissions:remote-path:local-path")

        # runcmd
        parser.add_argument("--runcmd", nargs='*', action=ExtendAction, help="run command on first boot")

        #
        parser.add_argument("--log", default='/dev/null', dest="logfile", help="Specifies the log file of root handler. By default, log to null device.")
        parser.add_argument("--loglevel", default='DEBUG', choices=list(LogLevelMap.keys()), help="Set logging level for log file, one of: ERROR,WARN,INFO,DEBUG - defaults to DEBUG")

        #
        parser.add_argument("--encrypt_key_prompt", action=EncryptKeyPromptAction, dest='encrypt_key', help="Key for encryption.")

        # Tell esc_monitor which IPs should be check
        parser.add_argument("--esc_monitor_check_ips", nargs="*", help="esc_monitor_check_ips")

        #
        parser.add_argument("--enable-http-rest", default=False, action='store_true', help="INSECURE! - NOT FOR PRODUCTION! Enable external REST interface over HTTP on port 8080.")
        parser.add_argument("--enable-https-rest", default=False, action='store_true', help="Enable external REST interface over HTTPS on port 8443.")

        # Authentication switch
        parser.add_argument("--enable-auth", default=False, action='store_true', help="Enable REST Api authentication.")

        # output formatter
        parser.add_argument("--format", default='table', choices=['json'], help="The output format, defaults to table.")
        parser.add_argument("--column", action=ExtendAction, nargs="*", help="specify the column(s) to print, can be repeated")

        # Support key/value pairs needed for compatibility with old bootvm.sh
        argsmap = {
            "os_auth_url": "--os_auth_url",
            "os_tenant_name": "--os_tenant_name",
            "os_username": "--os_username",
            "os_password": "--os_password",
            "esc_image_id": "--image",
            "esc_flavor_id": "--flavor",
            "hint": "--hint",
            "gateway_ip": "--gateway_ip",
            "avail_zone": "--avail_zone",
            "security_rules_file": "--security_rules_file",
            "esc_params_file": "--esc_params_file",
            "host_mapping_file": "--host_mapping_file",
            "esc_monitor_check_ips": "--esc_monitor_check_ips",
            "volume_id": "--db_volume_id",
            "ha_node_list": "--ha_node_list",
            "bgp_local_router_id": "--bgp_local_router_id",
            "kad_vif": "--kad_vif",
            "kad_vip": "--kad_vip",
            "kad_unicast_src_ip": "--kad_unicast_src_ip",
            "kad_unicast_peer": "--kad_unicast_peer",
            "bgp_remote_ip": "--bgp_remote_ip",
            "bgp_remote_as": "--bgp_remote_as",
            "bgp_local_ip": "--bgp_local_ip",
            "bgp_local_as": "--bgp_local_as",
            "bgp_anycast_ip": "--bgp_anycast_ip",
            "bgp_md5": "--bgp_md5",
            "rsyslog_server": "--rsyslog_server",
            "rsyslog_server_port": "--rsyslog_server_port",
            "rsyslog_server_protocol": "--rsyslog_server_protocol",
            "etc_hosts_file": "--etc_hosts_file",
            "ntp_server": "--ntp_server",
            "route": "--route",
            "user_pass": "--user_pass",
            "user_key": "--user_key",
            "user_confd_pass": "--user_confd_pass",
            "proxy": "--proxy",
            "noproxy": "--noproxy",
            "runcmd": "--runcmd",
            "log": "--log",
            "encrypt_key_prompt": "--encrypt_key_prompt",
        }

        args = []
        nets = []
        ipaddrs = []
        peer_ipaddrs = []
        nameservers = []
        ntp_servers = []

        skip_mapping = False

        for arg in argv[1:]:
            if arg.startswith('--'):
                if arg in parser._option_string_actions:
                    action = parser._option_string_actions[arg]

                    # tricky way to skip mapping
                    if action.metavar is not None and '=' in action.metavar:
                        skip_mapping = True
                    else:
                        skip_mapping = False

                if arg.lower() == "--version":
                    print(BOOTVM_VERSION)
                    exit(0)

                args.append(arg)
                continue

            if '=' in arg and not skip_mapping:
                kvpair = arg.split('=')
                key = kvpair[0]
                value = kvpair[1]

                mappedarg = argsmap.get(key)

                if mappedarg is not None:
                    args.extend([mappedarg, value])
                elif map_indexed_arg('net([0-9]*)_id', arg, nets):
                    pass
                elif map_indexed_arg('net([0-9]*)_ip', arg, ipaddrs):
                    pass
                elif map_indexed_arg('peer_net([0-9]*)_ip', arg, peer_ipaddrs):
                    pass
                elif map_indexed_arg('static([0-9]*)_ip', arg, ipaddrs):
                    # same as 'net_ip=<ipaddr>'
                    pass
                elif map_indexed_arg('nameserver([0-9]*)', arg, nameservers):
                    pass
                elif map_indexed_arg('ntp_server([0-9]*)', arg, ntp_servers):
                    pass
                else:
                    raise InvalidArgument(name=key)
            else:
                args.append(arg)

        # If multiple VIFs are attached to the same network, we could see the following error on old OpenStack:
        #   ERROR: Network 7af5c7df-6246-4d53-91bd-aa12a1607656 is duplicated. (HTTP 400) (Request-ID: req-eb3a49bf-2049-4bda-99bc-09e70420304f)
        #
        # http://specs.openstack.org/openstack/nova-specs/specs/juno/implemented/nfv-multiple-if-1-net.html
        # https://blueprints.launchpad.net/nova/+spec/multiple-if-1-net
        for net in nets:
            args.extend(['--net', net])

        for ipaddr in ipaddrs:
            args.extend(['--ipaddr', ipaddr])

        for peer_ipaddr in peer_ipaddrs:
            args.extend(['--peer_ipaddr', peer_ipaddr])

        for nameserver in nameservers:
            args.extend(['--nameserver', nameserver])

        for ntp_server in ntp_servers:
            args.extend(['--ntp_server', ntp_server])

        args = parser.parse_args(args = args)
        #print(args)
        #exit(0)

        logger.setLevel(LogLevelMap[args.loglevel])

        if args.logfile is not None:
            fileLogHandler = logging.FileHandler(args.logfile, 'a')
            fileLogFormatter = logging.Formatter('%(asctime)s: %(filename)s(%(lineno)d): %(levelname)s: %(message)s', None)
            fileLogHandler.setFormatter( fileLogFormatter)
            fileLogHandler.setLevel((LogLevelMap[args.loglevel]))
            rootLogger.addHandler(fileLogHandler)

        if args.format == 'json':
            jsonFormatter = JsonFormatter('%(message)s')
            stdoutLogHandler.setFormatter(jsonFormatter)
            stdoutLogHandler.emitLast()

        if args.libvirt is not None:
            vmm = LibVirtManager(args)
        else:
            vmm = OSManager(args)

        if args.ha is not None:
            # Check if all required options are provided.
            if args.ha == 1:
                if args.db_volume_id is None:
                    logger.info("missing db_volume_id. HA mode 1 require cinder volume. Creating one ...")
                    volume = vmm.create_volume(size=3, name="%s-db" % args.esc_hostname)
                    args.db_volume_id = volume.id
            elif args.ha == 2:
                if args.ha_node_list is None:
                    raise MissingHaNodeList()
                pass
            elif args.ha == 3:
                pass
        else:
            # for back-capatibility.
            if args.db_volume_id is not None:
                if args.ha_node_list is not None:
                    args.ha = 3
                else:
                    args.ha = 1
            else:
                if args.peer_ipaddr is not None or args.ha_node_list is not None:
                    args.ha = 2

        config_drives = []

        if args.ha:
            if args.kad_vip is not None and args.kad_vip.lower() == 'dhcp':
                 args.kad_vip = precreate_kad_vip(args)

            if args.kad_vip is None:
                if args.kad_vri is None:
                    raise MissingKadVri()

            if args.ha_node_list is None:
            #if False:
                # boot 2 vms for as HA pair
                args.ha_name = args.esc_hostname

                # update the esc hostname
                args.esc_hostname = "%s-%d" % (args.ha_name, 0)
                config_drives.append(ConfigDrive(args))

                # create the second args
                nargs = copy.deepcopy(args)

                nargs.esc_hostname = "%s-%d" % (args.ha_name, 1)
                # swap ipaddr and peer_ipaddr
                nargs.ipaddr = args.peer_ipaddr
                nargs.peer_ipaddr = args.ipaddr
                config_drives.append(ConfigDrive(nargs))
            else:
                # Do not boot 2 vms when ha_node_list is specified for back-capatibility
                args.ha_name = "esc_ha"
                config_drives.append(ConfigDrive(args))
        else:
            config_drives.append(ConfigDrive(args))

        for config_drive in config_drives:
            config_drive.compute_net_id()
            config_drive.check_esc_hostname()

        for config_drive in config_drives:
            if config_drive.args.ha == 3:
                if  config_drive.args.db_volume_id is None:
                    logger.info("missing db_volume_id. HA mode 3 require cinder volume. Creating one ...")
                    volume = vmm.create_volume(size=3, name="%s-db" % config_drive.args.esc_hostname)

                    while True:
                        volume = vmm.get_volume(volume.id)
                        if not volume.status == 'creating':
                            break
                        time.sleep(5)

                    config_drive.args.db_volume_id = volume.id

            # When building a ha/cluster, we need to know the IP peer node. pass config_drives...
            args, config_drive_etree = config_drive.build(config_drives)

            files = {}
            # check if there is None value
            if hasattr(config_drive_etree, 'iter'):
                ele_iter = config_drive_etree.iter()
            else:
                ele_iter = config_drive_etree.getiterator()

            for ele in ele_iter:
                for name, value in list(ele.attrib.items()):
                    if value is None:
                        raise NoneValue(name=name)

            # write out the config xml file
            config_drive_xml = xml.dom.minidom.parseString(
                    ET.tostring(
                     config_drive_etree,
                      'utf-8')).toprettyxml(indent="    ")
            #print(config_drive_xml)
            files['esc-config.xml'] = config_drive_xml

            if args.host_mapping_file != None:
                files['host-mapping-file.json'] = args.host_mapping_file

            esc_params_file = "/tmp/esc_params_file-%s-%s.conf" % (args.esc_hostname,os.getpid())

            if args.encrypt_key != None:
                with open(esc_params_file, "w") as f:
                    f.write("default.esc = %s\n" % args.encrypt_key)
            
            if not args.no_vim_credentials: 
                with open(esc_params_file, "a") as f:
                    f.write("openstack.os_auth_url = %s\n" % vmm.os_auth_url)
                    f.write("openstack.os_tenant_name = %s\n" % vmm.os_tenant_name)
                    if args.encrypt_key != None:
                        f.write("openstack.os_username = %s\n" % blowfish_encrypt(vmm.os_username, args.encrypt_key))
                        f.write("openstack.os_password = %s\n" % blowfish_encrypt(vmm.os_password, args.encrypt_key))
                    else:
                        f.write("openstack.os_username = %s\n" % vmm.os_username)
                        f.write("openstack.os_password = %s\n" % vmm.os_password)

            if args.esc_params_file != None:
                with open(esc_params_file, "a") as f:
                    with open(args.esc_params_file) as f2:
                        for line in f2:
                            f.write(line)

            if os.path.exists(esc_params_file):               
                files['esc_params.conf'] = open(esc_params_file, 'r').read()

            if args.security_rules_file is None:
                security_rules_file = "/tmp/net-sec-rules-%s-%s.json" % (args.esc_hostname,os.getpid())
                security_group_rule = build_security_group_rules()

                with open(security_rules_file, 'w') as f:
                    print(json.dumps(security_group_rule, sort_keys=True, indent=4), file=f)
            else:
                security_rules_file = args.security_rules_file

            files['net-sec-rules.json'] = open(security_rules_file, 'r').read()

            # display user-data and config-drive
            logger.debug("user-data:\n%s\n" % (config_drive.dump_user_data()))
            filesOutput = ''
            for k in files:
                filesOutput = "%s\n%s:\n%s" % (filesOutput, k, files[k])
            logger.debug("config-drive:\n%s\n" % filesOutput)

            if args.dryrun:
                user_data_file = "/tmp/user_data_file-%s-%s" % (args.esc_hostname,os.getpid())
                with open(user_data_file, "w") as f:
                    f.write(config_drive.dump_user_data())
                config_xml_file = "/tmp/config_xml_file-%s-%s" % (args.esc_hostname,os.getpid())
                with open(config_xml_file, "w") as f:
                    f.write(config_drive_xml)
                print("Passing files to nova create instance:")
                print(" --user-data %s" % (user_data_file))
                print(" --file esc-config.xml=%s" % (config_xml_file))
                print(" --file esc_params.conf=%s" % (esc_params_file))
                print(" --file net-sec-rules.json=%s" % (security_rules_file))

            if not args.dryrun:
                volume_id  = None

                if  args.db_volume_id is not None:
                    try:
                        volume = vmm.get_volume(args.db_volume_id)
                    except Exception as ex:
                        raise InvalidVolume(volume=args.db_volume_id)

                    if not volume.status == 'in-use' and not volume.status == 'available':
                        raise InvalidVolumeStatus(volume=args.db_volume_id, status=volume.status)

                if args.ha == 3 and args.db_volume_id is not None:
                    volume_id = args.db_volume_id

                hints = {}

                if args.hint:
                    for hint in args.hint:
                        key, _sep, value = hint.partition('=')

                        if key == 'different_host' or key == 'same_host':
                            server = vmm.get_server(value)

                            if not server:
                                raise InvalidServer(name=value)

                            value = server.id
                        elif key == 'group':
                            server_group = vmm.get_server_group(value)

                            if not server_group:
                                raise InvalidServerGroup(name=value)

                            value = server_group.id

                        if key in hints:
                            if isinstance(hints[key], six.string_types):
                                hints[key] = [hints[key]]
                            hints[key] += [value]
                        else:
                            hints[key] = value

                server = vmm.create_server(name=args.esc_hostname, image=args.image, flavor=args.flavor, files=files, userdata=config_drive.dump_user_data(), poll=args.poll, avail_zone=args.avail_zone, net=args.net, ipaddr=args.ipaddr, volume=volume_id, hints=hints)

                if not args.libvirt:
                    from novaclient import utils as nova_utils

                    server_info = server._info.copy()
                    server_info.pop('links')

                    if args.column:
                        server_info = { key: server_info[key] for key in args.column}

                    if args.format == 'table':
                        nova_utils.print_dict(server_info)
                    else:
                        #print(json.dumps(server_info, sort_keys=True, indent=4))
                        status = getattr(server, 'status').lower()

                        if status == 'active':
                            logger.info({"vm_uuid": server_info['id']})
                        else:
                            raise ServerInErrorState(name=server_info['name'], id=server_info['id'] )

                # add the vip into allowed-address-pairs if HA
                if args.kad_vip is not None and not args.libvirt:
                    vip_ip, vip_if = _vip(args.kad_vip)

                    for idx, net in enumerate(args.net):
                        if "eth%d" % (idx) == vip_if:
                            break

                    for port in vmm.get_port(network_id = net, device_id = server.id):
                        # should only return one port
                        # port_ip = port['fixed_ips'][0]['ip_address']
                        allowed_address_pairs = {"port": {"allowed_address_pairs": [{"ip_address": re.sub("/.*", "", vip_ip)}]}}
                        vmm.update_port(port['id'], allowed_address_pairs)

                servers.append(server)
    except BootVMException as ex:
        logger.exception(ex)
        exit(1)
    except Exception as ex:
        logger.exception(str(ex))
        exit(1)

    return servers

def _vip(vip):
    if not ":" in vip:
        # ipv4
        return vip, 'eth0'
    elif "]:" in vip:
        # [ipv6]:dev
        return re.sub('^\[', '', re.sub('\]:.*', '', vip)), re.sub('.*:', '', vip)
    elif "]" in vip:
        # [ipv6]
        return re.sub('^\[', '', re.sub('\]$', '', vip)), 'eth0'
    else:
        # ipv4:dev
        return re.sub(':.*', '', vip), re.sub('.*:', '', vip)

def blowfish_encrypt(plaintext, key):
    from Crypto.Cipher import Blowfish
    from struct import pack
    import base64

    bs = Blowfish.block_size
    cipher = Blowfish.new(key)
    plen = bs - divmod(len(plaintext),bs)[1]
    padding = [plen]*plen
    padding = pack('b'*plen, *padding)
    #return base64.b64encode(cipher.encrypt(plaintext + padding))
    return base64.b64encode(cipher.encrypt(plaintext.encode('utf-8') + padding))

'''
Modified from nova/utils.py
'''
def sanitize_hostname(hostname, default_name=None):
    """Return a hostname which conforms to RFC-952 and RFC-1123 specs except
       the length of hostname.

       Window, Linux, and Dnsmasq has different limitation:

       Windows: 255 (net_bios limits to 15, but window will truncate it)
       Linux: 64
       Dnsmasq: 63

       Due to nova-network will leverage dnsmasq to set hostname, so we chose
       63.

       """

    def truncate_hostname(name):
        if len(name) > 63:
            logger.warning("Hostname {} is longer than 63, truncate it to {}".format(name, name[:63]))
        return name[:63]

    if isinstance(hostname, six.text_type):
        # Remove characters outside the Unicode range U+0000-U+00FF
        hostname = hostname.encode('latin-1', 'ignore')
        if six.PY3:
            hostname = hostname.decode('latin-1')

    hostname = truncate_hostname(hostname)
    hostname = re.sub('[ _]', '-', hostname)
    hostname = re.sub('[^\w.-]+', '', hostname)
    hostname = hostname.lower()
    hostname = hostname.strip('.-')
    # NOTE(eliqiao): set hostname to default_display_name to avoid
    # empty hostname
    if hostname == "" and default_name is not None:
        return truncate_hostname(default_name)
    return hostname

if __name__ == "__main__":
    main(sys.argv)
