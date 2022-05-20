#
# Copyright 2019 Google LLC
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

import ssl
import time
import ldap3
import ldap3.utils.conv
from ldap3 import Tls
from ldap3.core.exceptions import LDAPException, LDAPStrongerAuthRequiredResult
import ldap3.core.exceptions
import logging
import dns.resolver
import json

class LdapException(Exception):
    pass

class NoSuchObjectException(LdapException):
    pass

class AlreadyExistsException(LdapException):
    pass

class DomainControllerLookupException(LdapException):
    pass

class ActiveDirectoryConnection(object):
    LDAP_ATTRIBUTE_PROJECT_ID    = "msDS-cloudExtensionAttribute1"
    LDAP_ATTRIBUTE_ZONE          = "msDS-cloudExtensionAttribute2"
    LDAP_ATTRIBUTE_INSTANCE_NAME = "msDS-cloudExtensionAttribute3"
    LDAP_ATTRIBUTE_GROUP_DATA    = "msDS-AzApplicationData"
    ACTIVE_DIRECTORY_GROUP_TYPE_DOMAIN_LOCAL = 4
    ACTIVE_DIRECTORY_GROUP_TYPE_SECURITY = -2147483648

    LDAP_OPERATION_RETRIES = 5

    def __init__(self, domain_controller, connection, base_dn):
        assert isinstance(connection, ldap3.Connection)
        self.__connection = connection
        self.__base_dn = base_dn
        self.__domain_controller = domain_controller

    def __to_scalar(self, value):
        if not value or len(value) == 0:
            return None
        else:
            return str(value)

    @staticmethod
    def locate_domain_controllers(domain_name, site_name):
        query = "_ldap._tcp"

        # Use site-awareness if site was provided
        if not site_name is None and len(site_name) > 0:
            query += f".{site_name}._sites"
            logging.info(f"Using site-awareness to select closest DC for site '{site_name}'")

        query += f".dc._msdcs.{domain_name}"

        records = dns.resolver.query(query, "SRV")
        if len(records) == 0:
            raise DomainControllerLookupException("No SRV records found for %s" % domain_name)

        records_sorted = sorted(records, key=lambda r: (-r.priority, r.weight, r.target))
        return [str(record.target)[:-1] if str(record.target).endswith(".") else str(record.target) for record in records_sorted]

    @staticmethod
    def connect(domain_controller, base_dn, user, password, use_ldaps=False, certificate_data=None):
        logging.info("Connecting to LDAP endpoint of '%s' as '%s'" % (domain_controller, user))

        if use_ldaps:
            logging.info("Using LDAP over SSL/TLS")
            tls_configuration = Tls(ssl.create_default_context(ssl.Purpose.SERVER_AUTH), validate=ssl.CERT_REQUIRED)

            if certificate_data is not None:
                logging.debug("Using CA certificate data from Secret Manager")
                tls_configuration.ca_certs_data = certificate_data

            server = ldap3.Server(domain_controller, port=636, connect_timeout=5, use_ssl=True, tls=tls_configuration)
        else:
            server = ldap3.Server(domain_controller, port=389, connect_timeout=5, use_ssl=False)

        connection = ldap3.Connection(server, user=user, password=password, authentication=ldap3.NTLM, raise_exceptions=True, receive_timeout=20)

        try:
            if connection.bind():
                return ActiveDirectoryConnection(domain_controller, connection, base_dn)
        except LDAPStrongerAuthRequiredResult:
            logging.exception("Failed to connect to LDAP endpoint: Active Directory requires LDAPS for NTLM binds")
        except LDAPException as e:
            logging.warn("Failed to connect to LDAP endpoint: %s" % e)

        # LDAP connection could not be established, raise exception
        raise LdapException("Connecting to LDAP endpoint of '%s' as '%s' failed" % (domain_controller, user))

    def get_domain_controller(self):
        return self.__domain_controller

    def find_ou(self, search_base_dn, name=None, includeDescendants=True):
        if name:
            filter = "(&(objectClass=organizationalUnit)(name=%s))" % ldap3.utils.conv.escape_filter_chars(name)
        else:
            filter = "(objectClass=organizationalUnit)"

        if includeDescendants:
            search_scope = ldap3.SUBTREE
        else:
            search_scope = ldap3.BASE
        try:
            self.__connection.search(
                search_filter=filter,
                search_base=search_base_dn,
                search_scope=search_scope,
                attributes=["distinguishedName", "name"])

            return [OrganizationalUnit(entry.entry_dn, self.__to_scalar(entry["name"]))
                for entry in self.__connection.entries]
        except ldap3.core.exceptions.LDAPNoSuchObjectResult:
            # In case OU was not found, return an empty array instead of raising an exception
            return []

    def find_computer(self, search_base_dn):
        # Search either for the specific group or in the base DN (but not its descendants)
        if search_base_dn.startswith("CN="):
            search_scope = ldap3.BASE
        else:
            search_scope = ldap3.LEVEL

        try:
            self.__connection.search(
                search_filter="(objectClass=computer)",
                search_base=search_base_dn,
                search_scope=search_scope,
                attributes=[
                    "distinguishedName",
                    "name",
                    ActiveDirectoryConnection.LDAP_ATTRIBUTE_PROJECT_ID,
                    ActiveDirectoryConnection.LDAP_ATTRIBUTE_ZONE,
                    ActiveDirectoryConnection.LDAP_ATTRIBUTE_INSTANCE_NAME])

            return [Computer(
                    entry.entry_dn,
                    self.__to_scalar(entry["name"]),
                    self.__to_scalar(entry[ActiveDirectoryConnection.LDAP_ATTRIBUTE_PROJECT_ID]),
                    self.__to_scalar(entry[ActiveDirectoryConnection.LDAP_ATTRIBUTE_ZONE]),
                    self.__to_scalar(entry[ActiveDirectoryConnection.LDAP_ATTRIBUTE_INSTANCE_NAME]))
                for entry in self.__connection.entries]
        except ldap3.core.exceptions.LDAPNoSuchObjectResult as e:
            raise NoSuchObjectException(e)

    def add_computer(self, ou, computer_name, upn, project_id, zone, instance_name):
        WORKSTATION_TRUST_ACCOUNT = 0x1000
        PASSWD_NOTREQD = 0x20

        dn = "CN=%s,%s" % (computer_name, ou)

        try:
            self.__connection.add(
                dn,
                [ # objectClass
                    "computer" ,
                    "organizationalPerson",
                    "person",
                    "user",
                    "top"
                ],
                {
                    # Mandatory attributes for a computer object.
                    "objectClass": "computer",
                    "sAMAccountName": computer_name + "$",
                    "userPrincipalName": upn,
                    "userAccountControl": WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD,
                    ActiveDirectoryConnection.LDAP_ATTRIBUTE_PROJECT_ID: project_id,
                    ActiveDirectoryConnection.LDAP_ATTRIBUTE_ZONE: zone,
                    ActiveDirectoryConnection.LDAP_ATTRIBUTE_INSTANCE_NAME: instance_name
                })

            return dn
        except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult as e:
            raise AlreadyExistsException(e)

    def remove_computer_upn(self, ou, computer_name):
        try:
            self.__connection.modify(
                "CN=%s,%s" % (computer_name, ou),
                {
                    "userPrincipalName": [(ldap3.MODIFY_DELETE, [])]
                })
        except ldap3.core.exceptions.LDAPAttributeOrValueExistsResult as e:
            raise AlreadyExistsException(e)

    def set_computer_upn(self, ou, computer_name, upn):
        try:
            self.__connection.modify(
                "CN=%s,%s" % (computer_name, ou),
                {
                    "userPrincipalName": [(ldap3.MODIFY_REPLACE, [upn])]
                })
        except ldap3.core.exceptions.LDAPAttributeOrValueExistsResult as e:
            raise AlreadyExistsException(e)

    def set_computer_zone(self, ou, computer_name, zone):
        try:
            self.__connection.modify(
                "CN=%s,%s" % (computer_name, ou),
                {
                    ActiveDirectoryConnection.LDAP_ATTRIBUTE_ZONE: [(ldap3.MODIFY_REPLACE, [zone])]
                })
        except ldap3.core.exceptions.LDAPAttributeOrValueExistsResult as e:
            raise AlreadyExistsException(e)

    def delete_computer(self, computer_dn):
        self.__connection.delete(computer_dn)

    def get_netbios_name(self):
        self.__connection.search(
            search_filter="(nETBIOSNAME=*)",
            search_base="CN=Partitions,CN=Configuration," + self.__base_dn,
            attributes=["nETBIOSNAME"])

        if len(self.__connection.entries) == 0:
            raise LdapException("Partitions information not found in directory")
        else:
            return self.__to_scalar(self.__connection.entries[0]["nETBIOSNAME"])

    def get_upn_by_samaccountname(self, samaccountname):
        if "\\" in samaccountname:
            samaccountname = samaccountname.split("\\")[1]

        self.__connection.search(
            search_filter="(&(objectClass=user)(sAMAccountName=%s))" % ldap3.utils.conv.escape_filter_chars(samaccountname),
            search_base=self.__base_dn,
            attributes=["userPrincipalName"])

        if len(self.__connection.entries) == 0:
            raise LdapException("User '%s' not found in directory" % samaccountname)
        else:
            return self.__to_scalar(self.__connection.entries[0]["userPrincipalName"])

    def find_group(self, search_base_dn):
        # Search either for the specific group or in the base DN (but not its descendants)
        if search_base_dn.startswith("CN="):
            search_scope = ldap3.BASE
        else:
            search_scope = ldap3.LEVEL

        try:
            self.__connection.search(
                search_filter="(&(objectClass=group))",
                search_base=search_base_dn,
                search_scope=search_scope,
                attributes=[
                    "distinguishedName",
                    "name",
                    ActiveDirectoryConnection.LDAP_ATTRIBUTE_GROUP_DATA,
                    ])

            return [Group(
                    entry.entry_dn,
                    self.__to_scalar(entry["name"]),
                    self.__to_scalar(entry[ActiveDirectoryConnection.LDAP_ATTRIBUTE_GROUP_DATA]))
                for entry in self.__connection.entries]
        except ldap3.core.exceptions.LDAPNoSuchObjectResult as e:
            raise NoSuchObjectException(e)

    def add_group(self, ou, group_name, project_id, zone, region):
        try:           
            metadata = {
                "project_id" : project_id,
                "zone" : zone,
                "region" : region
            }
            group_metadata = json.dumps(metadata)

            dn = "CN=%s,%s" % (group_name, ou)
            self.__connection.add(
                dn,
                [
                "group",
                "top"
                ],
                {
                    # Mandatory attributes for a computer object.
                    "groupType": self.ACTIVE_DIRECTORY_GROUP_TYPE_DOMAIN_LOCAL + self.ACTIVE_DIRECTORY_GROUP_TYPE_SECURITY,
                    "objectClass": "group",
                    "name": group_name,
                    "description" : "Group for computers of MIG '%s'" % (group_name),
                    ActiveDirectoryConnection.LDAP_ATTRIBUTE_GROUP_DATA: group_metadata
                })
            return dn
        except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult as e:
            raise AlreadyExistsException(e)
    
    def add_member_to_group(self, ou, group_name, computer_dn):
        retries = 0

        while retries < self.LDAP_OPERATION_RETRIES:
            try:
                self.__connection.modify(
                    "CN=%s,%s" % (group_name, ou),
                    {
                        'member': [(ldap3.MODIFY_ADD, [computer_dn])]
                    })
                break
            except ldap3.core.exceptions.LDAPBusyResult:
                logging.warn(f"LDAP endpoint is busy, retrying operation 'add_member_to_group' for '{computer_dn}'")
                retries += 1
                time.sleep(1)
            except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult as e:
                logging.info(f"'{computer_dn}' already part of '{group_name}'")
                pass
    
    def delete_group(self, group_dn):
        self.__connection.delete(group_dn)

    def get_user(self):
        return self.__connection.user

class NamedObject(object):
    def __init__(self, dn, name):
        self.__dn = dn
        self.__name = name

    def get_dn(self):
        return self.__dn

    def get_name(self):
        return self.__name

class OrganizationalUnit(NamedObject):
    pass

class Computer(NamedObject):
    def __init__(self, dn, name, project_id, zone, instance_name):
        super(Computer, self).__init__(dn, name)
        self.__project_id = project_id
        self.__zone = zone
        self.__instance_name = instance_name
    
    def get_instance_name(self):
        return self.__instance_name

    def get_zone(self):
        return self.__zone

    def get_project_id(self):
        return self.__project_id

class Group(NamedObject):
    def __init__(self, dn, name, group_metadata):
        super(Group, self).__init__(dn, name)
        if group_metadata:
            metadata = json.loads(group_metadata)
        else:
            metadata = {}
        self.__region = metadata.get("region")
        self.__zone = metadata.get("zone")
        self.__project_id = metadata.get("project_id")
    
    def get_project_id(self):
        return self.__project_id
    
    def get_region(self):
        return self.__region
    
    def get_zone(self):
        return self.__zone