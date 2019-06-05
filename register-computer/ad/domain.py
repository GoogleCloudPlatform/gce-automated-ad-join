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

import socket
import ldap3
import ldap3.utils.conv
import ldap3.core.exceptions
import logging
import datetime
import dns.resolver

class LdapException(Exception):
    pass

class AlreadyExistsException(LdapException):
    pass

class DomainControllerLookupException(LdapException):
    pass

class ActiveDirectoryConnection(object):
    LDAP_ATTRIBUTE_PROJECT_ID    = "msDS-cloudExtensionAttribute1"
    LDAP_ATTRIBUTE_ZONE          = "msDS-cloudExtensionAttribute2"
    LDAP_ATTRIBUTE_INSTANCE_NAME = "msDS-cloudExtensionAttribute3"

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
    def locate_domain_controllers(domain_name):
        records = dns.resolver.query("_ldap._tcp.dc._msdcs.%s" % domain_name, "SRV")
        if len(records) == 0:
            raise DomainControllerLookupException("No SRV records found for %s" % domain_name)

        records_sorted = sorted(records, key=lambda r: (-r.priority, r.weight))
        return [str(record.target) for record in records_sorted]

    @staticmethod
    def connect(domain_controller, base_dn, user, password):
        logging.info("Connecting to LDAP endpoint of '%s' as '%s'" % (domain_controller, user))
        connection = ldap3.Connection(
            server=ldap3.Server(
                domain_controller,
                port=389,
                connect_timeout=5),
            user=user,
            password=password,
            authentication=ldap3.NTLM,
            raise_exceptions=True)

        if not connection.bind():
            raise LdapException("Connecting to LDAP endpoint of %s as '%s' failed, check credentials" %
                (domain_controller, user))

        return ActiveDirectoryConnection(domain_controller, connection, base_dn)

    def get_domain_controller(self):
        return self.__domain_controller

    def find_ou(self, search_base_dn, name=None):
        if name:
            filter = "(&(objectClass=organizationalUnit)(name=%s))" % ldap3.utils.conv.escape_filter_chars(name)
        else:
            filter = "(objectClass=organizationalUnit)"

        self.__connection.search(
            search_filter=filter,
            search_base=search_base_dn,
            attributes=["distinguishedName", "name"])

        return [OrganizationalUnit(entry.entry_dn, self.__to_scalar(entry["name"]))
            for entry in self.__connection.entries]

    def find_computer(self, search_base_dn):
        self.__connection.search(
            search_filter="(objectClass=computer)",
            search_base=search_base_dn,
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
