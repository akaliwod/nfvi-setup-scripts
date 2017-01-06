#!/usr/bin/env python
from __future__ import print_function

import argparse
import copy
import json
import logging
import os
import random
import re
import socket
import string
import subprocess
import sys
import traceback
import crypt
import random
import base64

import xml.dom.minidom
import xml.etree.cElementTree as ET

from cinderclient import client as cinderclient
from novaclient import client as novaclient
from neutronclient.v2_0 import client as neutronclient
from neutronclient.common import exceptions

from netaddr import *

BOOTVM_VERSION = "ESC-2_2_3_26"

class ConfigDrive():
    def __init__(self, args):
        self.args = args

        # if --secure option is used without providing a key with --user_pass. How else can the you ssh into the ESC VM ?
        if args.secure:
            need_user_pass_key=True

            if args.user_pass is not None:
                for user, password, key in self.enumerateUPK(args.user_pass):
                    if key:
                        need_user_pass_key=False

            if need_user_pass_key:
                logger.error("--secure option is given. ESC VM is not accessible without a key. Please specify the public key by '--user_pass'.")
                exit(1)

        self.user_data = "#cloud-config"

        # check the hostname. see rfc952 and rfc1123
        re_hostname = re.compile("^[a-z0-9][a-z0-9\-]*[a-z0-9]$", re.IGNORECASE)

        if not re_hostname.match(args.esc_hostname):
            logger.warn("Hostname contains characters that are not allowed by rfc1123.")

        self.user_data = "%s\n%s" % (self.user_data, "hostname: %s" % args.esc_hostname)

        # ssh_pwauth
        if self.args.secure:
            # Disable ssh password authentication
            self.user_data = "%s\n%s" % (self.user_data, "ssh_pwauth: False")
        else:
            # Enable SSH password authentication
            self.user_data = "%s\n%s" % (self.user_data, "ssh_pwauth: True")

        # bootcmd
        self.user_data = "%s\n%s" % (self.user_data, "bootcmd:")

        # This hook is need configure esc_ui job for automatic startup, and kickstart it the first time
        # If esc_ui_startup is false, esc_ui will remain in manual startup configuration
        if self.args.esc_ui_startup:
            self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, esc_ui_startup, sh, -c, \"$(esc_version -p | awk '{printf $NF}')/esc-init/enable_esc_ui\"]")

        # Disable root login
        self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, disable_root_login, sh, -c, \"sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config\"]")

        if self.args.secure:
            # Enable iptables:
            self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, turnon_iptables, sh, -c, \"chkconfig iptables on\"]")
            self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, turnon_ip6tables, sh, -c, \"chkconfig ip6tables on\"]")
            self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, copy_iptables, sh, -c, \"cp $(esc_version -p | awk '{printf $NF}')/esc-init/iptables /etc/sysconfig\"]")
            self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, copy_ip6tables, sh, -c, \"cp $(esc_version -p | awk '{printf $NF}')/esc-init/ip6tables /etc/sysconfig\"]")

            # Re-create host keys for confd
            self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, confd_ssh_keygen, sh, -c, \"echo y | ssh-keygen -t dsa -f $(esc_version -p | awk '{printf $NF}')/esc_database/confd-keydir/ssh_host_dsa_key -N ''\"]")

            # Re-create keys for confd admin user
            recreate_confd_admin_key = True

            if self.args.user_confd_pass is not None:
                for user, password, key in self.enumerateUPK(self.args.user_confd_pass):
                    if user == 'admin' and key:
                        # should not create the re-create the keys as the public is passed in.
                        recreate_confd_admin_key = False

            if recreate_confd_admin_key:
                self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, confd_admin_keygen, sh, -c, \"echo y | ssh-keygen -t dsa -f /var/confd/homes/admin/.ssh/confd_id_dsa -N ''\"]")
                self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, confd_admin_copy_key, sh, -c, \"cp /var/confd/homes/admin/.ssh/confd_id_dsa.pub /var/confd/homes/admin/.ssh/authorized_keys\"]")

            # Turn on selinux
            self.user_data = "%s\n%s" % (self.user_data, " - setenforce 1")

        # runcmd
        self.user_data = "%s\n%s" % (self.user_data, "runcmd:")

        if self.args.route:
            # The route configuration file is generated after network is up. we need to restart the network to re-configure route.
            self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, restart_network, sh, -c, \"service network restart\"]")

        # confd is running as tomcat.
        self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, confd_ssh_chown_tomcat, sh, -c, \"chown -R tomcat:tomcat /var/confd/homes/admin/.ssh/\"]")

        if self.args.secure:
            # We need to start iptables/ip6tables manually for the first time.
            self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, start_iptables, sh, -c, \"service iptables start\"]")
            self.user_data = "%s\n%s" % (self.user_data, " - [ cloud-init-per, once, start_ip6tables, sh, -c, \"service ip6tables start\"]")

        # Manage /etc/hosts by cloud-init
        if self.args.etc_hosts_file is None:
            self.user_data = "%s\n%s" % (self.user_data, "manage_etc_hosts: true")

        self.nova = novaclient.Client('2', *self.getBootstrapOpenStackCredentials())

    def check_esc_hostname(self):
        for server in self.nova.servers.list():
            if server.name == self.args.esc_hostname:
                logger.error("There is already a server with name '%s'. Please use another name." % (self.args.esc_hostname))
                exit(1)

    def get_port(self, net_id, ip):
        ports = neutron.list_ports(fields=('id', 'network_id', 'fixed_ips', 'device_id'))['ports'];

        for port in ports:
            if port['network_id'] == net_id and port['fixed_ips'][0]['ip_address'] == ip and port['device_id'] == '':
                return(port)

        return None

    def create_port(self, net, port_name=None, ip=None):
        body_value = { "port": {
                        "admin_state_up": True,
                        "name": port_name,
                        "network_id": net
                                }
                        }
        if not ip is None:
            body_value['port']['fixed_ips'] = [{"ip_address": ip}]

        return neutron.create_port(body=body_value)['port']

    def precreate_ports(self):
        # Keep all pre-created ports. When 'nova boot' fails and no instance is created, we should delete them.
        self.precreated_ports = []
        args = self.args

        for idx, net, ipaddr in self.enumerateNetIP(args.net, args.ipaddr):
            # print idx, net, ipaddr
            port = None

            if args.dryrun:
                logger.info("DRYRUN: skipping port creation")
            else:
                try:
                    # create port manually
                    port_name = "%s-port-%s-%d" % (args.esc_hostname, magicstr, idx)
                    port = self.create_port(net, port_name, str(ipaddr.ip) if ipaddr is not None else None)

                    if args.ha and "eth%d" % (idx) == args.kad_vif:
                        try:
                            neutron.show_extension("allowed-address-pairs")
                            allowed_address_pairs = {"port": {"allowed_address_pairs": [{"ip_address": args.kad_vip}]}}
                            neutron.update_port(port['id'], allowed_address_pairs)
                        except exceptions.NeutronClientException as ex:
                            # If there is no "allowed-address-pairs", print a WARN.
                            if ex.status_code == 404:
                                logger.warn("OpenStack doesn't have allowed-address-pairs extention. You might not be able to access your vip.")
                            else:
                                logger.exception("NeutronClientException")

                except exceptions.IpAddressInUseClient as ex:
                    port = self.get_port(net, str(ipaddr.ip))

                    if not port:
                        logger.error(ex)

                        # TODO: Should create a hook to call delete_precreated_ports() while exiting?
                        self.delete_precreated_ports()
                        exit(1)

                    # There is aleady free pre-created port. use it.
                except Exception as ex:
                    print(type(ex).__name__)
                    # Some OpenStack setup uses fake ip pool. failover to net.
                    logger.warn("Cannot create the port for ipaddr:%s, net:%s" % (ipaddr, net))
                    logger.warn("I'm assuming your OpenStack setup is using a fake ip pool. Failover to net.")

            self.precreated_ports.append(port)

    def build(self, config_drives):
        self.config_drives = config_drives
        return self.args, self.build_esc()

    # build the root element of config drive
    def build_esc(self):
        esc = ET.Element("esc")

        esc.set("version", BOOTVM_VERSION)
        argv = "%s %s" % (' '.join(sys.argv), args)
        esc.set("argv", base64.b64encode(argv))

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
        if self.args.db_volume_id is not None:
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
                disk = "/dev/disk/by-id/virtio-%s" % (self.args.db_volume_id[:20])
                drbd.set("disk", disk)

                self.write_hahook_file(esc_cloud, args.esc_hostname, args.db_volume_id, disk)

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
        for idx, net, ipaddr in self.enumerateNetIP(self.args.net, self.args.ipaddr):
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

            self.user_data = "%s\n%s" % (self.user_data, "write_files:")
            self.user_data = "%s\n%s" % (self.user_data, "  - content: |")
            self.user_data = "%s\n%s" % (self.user_data, "      %s via %s" % (net, gw))
            self.user_data = "%s\n%s" % (self.user_data, "    path: /etc/sysconfig/network-scripts/route-%s" % (dev))

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
        for idx, net, ipaddr in self.enumerateNetIP(self.args.net, self.args.ipaddr, idx):
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
                logger.error("invalid format for --user_pass %s" % (upk))
                exit(1)

            if k != "":
                if  not os.path.exists(k):
                    logger.error("key file '%s' doesn't exist." % (k))
                    exit(1)
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
        self.user_data = "%s\n%s" % (self.user_data, "users:")

        # Disable root login
        if self.args.secure:
            self.user_data = "%s\n%s" % (self.user_data, "  - name: root")
            self.user_data = "%s\n%s" % (self.user_data, "    lock-passwd: true")

        if self.args.user_pass is not None:
            user_pass = self.args.user_pass
        else:
            # default username and password
            user_pass = ['admin:cisco123']

        for user, password, key in self.enumerateUPK(user_pass):
            self.user_data = "%s\n%s" % (self.user_data, "  - name: %s" % user)
            self.user_data = "%s\n%s" % (self.user_data, "    gecos: %s" % "User created by cloud-init")
            # TODO: Should it better to use sha512 hashed password?
            #print(">>>> %s:%s:%s" % (user, password, key))

            if password != "":
                self.user_data = "%s\n%s" % (self.user_data, "    passwd: %s" % crypt.crypt(password, 'xy'))
                self.user_data = "%s\n%s" % (self.user_data, "    lock-passwd: false")

            if key != "":
                self.user_data = "%s\n%s" % (self.user_data, "    ssh-authorized-keys:")
                self.user_data = "%s\n%s" % (self.user_data, "      - %s" % key)

            self.user_data = "%s\n%s" % (self.user_data, "    sudo: ALL=(ALL) ALL")

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

        # TODO: needs to check if vip is IPV6
        if not "/" in self.args.kad_vip:
            keepalived.set("virtual_ipaddress", "%s/24" % (self.args.kad_vip))
        else:
            keepalived.set("virtual_ipaddress", self.args.kad_vip)

        keepalived.set("interface", self.args.kad_vif)

        vri = self.args.kad_vri
        if vri is not None:
            keepalived.set("virtual_router_id", vri)

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

            self.user_data = "%s\n%s" % (self.user_data, "rsyslog:")
            self.user_data = "%s\n%s" % (self.user_data, "  - \"*.* %s[%s]:%s\"" % (protocolspecifier, logserver, logserverport))

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
        if volume_id is not None:
            cinder = cinderclient.Client('1', *self.getBootstrapOpenStackCredentials())

            try:
                volume = cinder.volumes.get(volume_id)
            except Exception as ex:
                logger.error("Cannot retrieve volume: %s" % (volume_id))
                logger.exception("Exception while retrieving volume")
                exit(1)

            if not volume.status == 'in-use' and not volume.status == 'available':
                logger.error("You cannot use the volume in '%s' status" % (volume.status))
                exit(1)

        # we support 4 user cases: 
        # 0, database volume in standalone ESC
        # 1, shared database volume in HA
        # 2, DRBD in HA
        # 3, volume + DRBD in HA

        disk = ET.SubElement(esc_service, "disk")

        # TODO: script needs cleanup
        if self.args.ha == 2:
            # case 2
            logger.info("ESC HA supports two options for database, external volume and built-in DRBD. If  you want to use external volume, please specify it with '--db_volume_id DB_VOLUME_ID'")
            logger.info("I'm assuming you want to use built-in DRBD...")
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
        port.text = "4321"

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

    def getBootstrapOpenStackCredentials(self):
        bs_os_auth_url      = self.args.bs_os_auth_url
        bs_os_tenant_name   = self.args.bs_os_tenant_name
        bs_os_username      = self.args.bs_os_username
        bs_os_password      = self.args.bs_os_password

        return bs_os_username, bs_os_password, bs_os_tenant_name, bs_os_auth_url

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

    def enumerateNetIP(self, nets, ipaddrs, index=-1):
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
                networks = neutron.list_networks(fields="subnets", name=net)['networks']

                if len(networks) == 0:
                    # Try network id
                    networks = neutron.list_networks(fields="subnets", id=net)['networks']

                for subnet_id in networks[0]['subnets']:
                    subnet = IPNetwork(neutron.show_subnet(subnet_id)['subnet']['cidr'])
                    if subnet.__contains__(ipnetwork.ip):
                        # The subnet range contains the ip. Use the prefixlen defined.
                        if not ipnetwork.prefixlen == subnet.prefixlen:
                            logger.warn("The prefixlen doesn't match the one defined in subnet. Use /%d instead of /%d." % (subnet.prefixlen, ipnetwork.prefixlen))
                            ipnetwork.prefixlen = subnet.prefixlen
                        break

            if index == -1:
                yield idx, net, ipnetwork
            else:
                if index == idx:
                    yield idx, net, ipnetwork
                else:
                    continue

    def delete_precreated_ports(self):
        for port in self.precreated_ports:
            # We should check if port is in-use
            # https://bugs.launchpad.net/neutron/+bug/1314614
            port = neutron.show_port(port['id'])['port']
            name_prefix = "%s-port-%s" % (self.args.esc_hostname, magicstr)

            if port['device_id'] == '' and port['name'].startswith(name_prefix):
                logger.info("Deleting precreated port: %s" % (port['id']))
                neutron.delete_port(port['id'])

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

class GetNetIDAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        #print '%r %r %r' % (namespace, values, option_string)
        net_ids = getattr(namespace, self.dest)

        if net_ids is None:
            net_ids = []

        for idx, net in enumerate(values):
            if net is None:
                err = "Invalid network %s, idx=%d" % (net, idx)
                logger.error("%s" % (err))
                raise GetNetIdError(err)

            rc, out, err = runCmd("neutron", "net-show", net, "-F", "id", "-f", "shell")

            if rc != 0:
                logger.error("Invalid network: %s, err: %s" % (net, err))
                raise GetNetIdError(err)

            net_id = re.search('id="(.*)"', out).group(1)
            net_ids.append(net_id)

        setattr(namespace, self.dest, net_ids)

def build_security_group_rules():
    security_group_rules = []
    security_group_rules.append(build_security_group_rule(-1, "icmp", -1))
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

    logger.warn("Invalid parameter for esc_ui_startup, %s, defaulted to False" % (value))
    logger.warn("      Valid choice: { yes | true | 1 | no | false | 0 }")

    return True

def compute_net_id(args):
    if args.net is None:
        networks = neutron.list_networks(fields="id")['networks']

        if len(networks) != 1:
            logger.error("Multiple network matches found, please specify the network with --net.")
            exit(1)
        else:
            args.net = [networks[0]['id']]
            return

    net_ids = []
    for net in args.net:
        networks = neutron.list_networks(fields="id", id=net)['networks']

        if len(networks) == 0:
            networks = neutron.list_networks(fields="id", name=net)['networks']

        if len(networks) == 0:
            logger.error("Unable to find network with name or id '%s'." % (net))
            exit(1)
        elif len(networks) != 1:
            logger.error("Multiple network matches found for name '%s', use an ID to be more specific." % (net))
            exit(1)
        else:
            net_id = networks[0]['id']
            net_ids.append(net_id)

    args.net = net_ids

def create_port(net, port_name=None, ip=None):
    body_value = { "port": {
                    "admin_state_up": True,
                    "name": port_name,
                    "network_id": net
                            }
                    }
    if not ip is None:
        body_value['port']['fixed_ips'] = [{"ip_address": ip}]

    return neutron.create_port(body=body_value)['port']

def precreate_kad_vip(args):
    net_idx = int(args.kad_vif.strip('eth'))
    net = args.net[net_idx]
    port_name = "%s-port-%s-VIP" % (args.esc_hostname, magicstr)
    port = create_port(net, port_name)

    kad_vip = port['fixed_ips'][0]['ip_address']
    logger.info("The kad virtual ipaddress is created automatically: %s" % (kad_vip))

    return kad_vip

def check_ha_mode(value):
    ivalue = int(value)

    if ivalue < 0 or ivalue > 3:
        logger.warn("Valid HA mode: 1: Shared Cinder Volume, 2: Built-in DRBD, 3: DRBD over Cinder Volume")
        raise argparse.ArgumentTypeError("%s is an invalid HA mode" % value)

    return ivalue

if __name__ == "__main__":
    # A magic random string. Right now I'm using it to generate port names.
    magicstr = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    hdlr = logging.StreamHandler(sys.stdout)
    logger_formatter = logging.Formatter('%(asctime)s: %(filename)s(%(lineno)d): %(levelname)s: %(message)s', None)
    hdlr.setFormatter(logger_formatter)
    logger.addHandler(hdlr)

    try:
        parser = argparse.ArgumentParser(description='Boot ESC VM into an openstack.', add_help=True)

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
        os_group.add_argument("--os_auth_url",  help="Defaults to env[OS_AUTH_URL].")
        os_group.add_argument("--os_tenant_name",  help="Defaults to env[OS_TENANT_NAME].")
        os_group.add_argument("--os_username",  help="Defaults to env[OS_USERNAME].")
        os_group.add_argument("--os_password",  help="Defaults to env[OS_PASSWORD].")

        # HA. By default, HA is disabled. depeciated, use '--cluster' instead
        ha_group = parser.add_argument_group('ha arguments')
        ha_group.add_argument("--ha", type=check_ha_mode, help="Define the HA mode. 0: No HA, 1: Shared Cinder Volume, 2: Built-in DRBD, 3: DRBD over Cinder Volume")

        # Cluster
        cluster_group = parser.add_argument_group('cluster arguments')
        cluster_group.add_argument("--cluster", type=int, nargs='?', const=2, help="Enable cluster.")
        cluster_group.add_argument("--vip", help="virtual ipaddress of esc cluster")

        # keepalived
        ha_group.add_argument("--kad_vip", help="virtual ipaddress of vrrp instance")
        ha_group.add_argument("--kad_vif", default='eth0', help="interface of vrrp instance")
        ha_group.add_argument("--kad_vri", help="virtual router id of vrrp instance. Use the last byte of vip if it's not specified, ")

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
        nw_group.add_argument("--net", nargs='*', action=ExtendAction, help="On the ESC VM, create a NIC attached to network with this ID or name.")
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
        parser.add_argument("--group", help="Specify OpenStack affinity or anti-affinity group.")
        parser.add_argument("--avail_zone", default="nova", help="The availability zone for ESC VM placement.")
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
        parser.add_argument("--esc_ui_startup", default=False, type=esc_ui_startup, help="Control automatic startup of ESC UI.  If disabled with false|no, esc_ui process can be started manually on ESC VM after instalation.")

        #
        parser.add_argument("--log", help="Specifies the log file. By default, log to stdout.")

        # Tell esc_monitor which IPs should be check
        parser.add_argument("--esc_monitor_check_ips", nargs="*", help="esc_monitor_check_ips")

        #
        parser.add_argument("--enable-http-rest", default=False, action='store_true', help="INSECURE! - NOT FOR PRODUCTION! Enable external REST interface over HTTP on port 8080.")
        parser.add_argument("--enable-https-rest", default=False, action='store_true', help="Enable external REST interface over HTTPS on port 8443.")

        # Authentication switch 
        parser.add_argument("--enable-auth", default=False, action='store_true', help="INSECURE! - REST Api authentication disabled.")
        # Support key/value pairs needed for compatibility with old bootvm.sh
        argsmap = {
            "os_auth_url": "--os_auth_url",
            "os_tenant_name": "--os_tenant_name",
            "os_username": "--os_username",
            "os_password": "--os_password",
            "esc_image_id": "--image",
            "esc_flavor_id": "--flavor",
            "group": "--group",
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
            "log": "--log",
        }

        args = []
        nets = []
        ipaddrs = []
        peer_ipaddrs = []
        nameservers = []
        ntp_servers = []

        for arg in sys.argv[1:]:
            if arg.startswith('--'):
                if arg.lower() == "--version":
                    print(BOOTVM_VERSION)
                    exit(0)

                args.append(arg)
                continue

            if '=' in arg:
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
                    print("ERROR: unrecognized argument: %s" % (key))
                    exit(1)
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

        if args.log is not None:
            hdlr = logging.FileHandler(args.log, 'a')

        hdlr.setFormatter(logger_formatter)
        logger.addHandler(hdlr)

        # Handle default value assignment for OpenStack credentials (openrc)
        if args.os_auth_url is None:
           args.os_auth_url = args.bs_os_auth_url
        if args.os_tenant_name is None:
           args.os_tenant_name = args.bs_os_tenant_name
        if args.os_username is None:
           args.os_username = args.bs_os_username
        if args.os_password is None:
           args.os_password = args.bs_os_password

        if not args.os_auth_url or len(args.os_auth_url) == 0:
            logger.error("missing os_auth_url.  Check command line or source openrc first.")
            exit(1)

        if not args.bs_os_auth_url or len(args.bs_os_auth_url) == 0:
            logger.error("missing bs_os_auth_url.  Check command line or source openrc first.")
            exit(1)

        # append / to end of os_auth_url
        if not args.os_auth_url.endswith('/'):
            args.os_auth_url += '/'
        if not args.bs_os_auth_url.endswith('/'):
            args.bs_os_auth_url += '/'

        neutron = neutronclient.Client(username=args.bs_os_username,
                                    password=args.bs_os_password,
                                    tenant_name=args.bs_os_tenant_name,
                                    auth_url=args.bs_os_auth_url)

        compute_net_id(args)

        if args.ha is not None:
            # Check if all required options are provided.
            if args.ha == 1 or args.ha == 3:
                # db_volume_id
                if args.db_volume_id is None:
                    logger.error("missing db_volume_id. HA mode 1 and 3 require cinder volume.")
                    exit(1)
            elif args.ha == 2:
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
            if args.kad_vip is None or args.kad_vip.lower() == 'dhcp':
                if args.kad_vip is None:
                    logger.warn("The kad virtual ipaddress is mandatory for ESC HA. You can specify it with '--kad_vip KAD_VIP' or '--kad_vip dhcp'")
                    logger.info("I'm assuming you want to create a VIP automatically.")
                args.kad_vip = precreate_kad_vip(args)

            #if args.ha_node_list is None:
            if False:
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
            config_drive.check_esc_hostname()
            config_drive.precreate_ports()

        if len(config_drives) > 1 and args.ha_node_list is None:
            # compute ha_node_list
            net_idx = int(args.kad_vif.strip('eth'))
            ha_node_list = []

            for i in range(0, len(config_drives)):
                config_drive  = config_drives[i]
                port = config_drive.precreated_ports[net_idx]
                ip = port['fixed_ips'][0]['ip_address']
                ha_node_list.append(ip)

            for config_drive in config_drives:
                config_drive.args.ha_node_list = ha_node_list

        for config_drive in config_drives:
            # When building a ha/cluster, we need to know the IP peer node. pass config_drives...
            args, config_drive_etree = config_drive.build(config_drives)

            cmd = "nova --os-username '%s' --os-password '%s' --os-tenant-name '%s' --os-auth-url '%s' boot" % (config_drive.getBootstrapOpenStackCredentials())
            if args.poll:
                cmd = "%s %s" % (cmd, "--poll")

            if args.group:
                cmd = "%s %s" % (cmd, "--hint group=%s" % args.group)

            cmd = "%s %s '%s'" % (cmd, "--image", args.image)
            cmd = "%s %s '%s'" % (cmd, "--flavor", args.flavor)
            cmd = "%s %s '%s'" % (cmd, "--availability-zone", args.avail_zone)

            # Create a user-data file to enable ssh password authentication
            user_data_file = "/tmp/user-data.%s-%s" % (args.esc_hostname, os.getpid())
            with open(user_data_file, "w") as f:
                f.write("%s\n" % config_drive.user_data)

            cmd = "%s %s" % (cmd, "--user-data %s" % user_data_file)

            for idx, port in enumerate(config_drive.precreated_ports):
                if port is not None:
                    cmd = "%s --nic port-id=%s" % (cmd, port['id'])
                else:
                    cmd = "%s --nic net-id=%s" % (cmd, args.net[idx])

            if args.host_mapping_file != None:
                cmd = "%s %s%s" % (cmd, "--file host-mapping-file.json=", args.host_mapping_file)

            esc_params_file = "/tmp/esc_params_file-%s-%s.conf" % (args.esc_hostname,os.getpid())

            with open(esc_params_file, "w") as f:
                f.write("openstack.os_auth_url = %s\n" % args.os_auth_url)
                f.write("openstack.os_tenant_name = %s\n" % args.os_tenant_name)
                f.write("openstack.os_username = %s\n" % args.os_username)
                f.write("openstack.os_password = %s\n" % args.os_password)

            if args.esc_params_file != None:
                with open(esc_params_file, "a") as f:
                    with open(args.esc_params_file) as f2:
                        for line in f2:
                            f.write(line)

            cmd = "%s %s%s" % (cmd, "--file esc_params.conf=", esc_params_file)

            if args.security_rules_file is None:
                security_rules_file = "/tmp/net-sec-rules-%s-%s.json" % (args.esc_hostname,os.getpid())
                security_group_rule = build_security_group_rules()

                with open(security_rules_file, 'w') as f:
                    print(json.dumps(security_group_rule, sort_keys=True, indent=4), file=f)
            else:
                security_rules_file = args.security_rules_file

            cmd = "%s %s%s" % (cmd, "--file net-sec-rules.json=", security_rules_file)

            # check if there is None value
            for ele in config_drive_etree.iter():
                for name, value in list(ele.attrib.items()):
                    if value is None:
                        logger.error("%s is None" % (name))
                        exit(1)

            # write out the config xml file
            config_drive_xml = xml.dom.minidom.parseString(
                    ET.tostring(
                     config_drive_etree,
                      'utf-8')).toprettyxml(indent="    ")

            config_drive_xml_file = "/tmp/esc-config-%s-%s.xml" % (args.esc_hostname,os.getpid())
            with open(config_drive_xml_file, 'w') as f:
                print(config_drive_xml, file=f)
            #print(config_drive_xml)
            #exit(1)

            cmd = "%s %s%s" % (cmd, "--file esc-config.xml=", config_drive_xml_file)

            cmd = "%s %s" % (cmd, "--config-drive=true")
            cmd = "%s '%s'" % (cmd, args.esc_hostname)

            logger.info(cmd)
            print()
            if not args.dryrun:
                rc, out, err = runCmd(["-c", cmd])

                if not out == "":
                    logger.info("Stdout:\n%s" % (out))

                if not err == "":
                    logger.error("Stderr: %s" % (err))

                if rc != 0:
                    config_drive.delete_precreated_ports()
                    exit(rc)

    except novaclient.exceptions.Unauthorized as ex:
        logger.error('''Please check the credentials of OpenStack to bootstrap ESC VM:
            bs_os_username      = %s
            bs_os_password      = %s
            bs_os_tenant_name   = %s
            bs_os_auth_url      = %s
            ''' % (config_drive.getBootstrapOpenStackCredentials()))
        logger.exception("novaclient.exceptions.Unauthorized")
    except KeyboardInterrupt as ex:
        config_drvie.delete_precreated_ports()
    except Exception as ex:
        logger.exception("Unknown exception")
        config_drive.delete_precreated_ports()
