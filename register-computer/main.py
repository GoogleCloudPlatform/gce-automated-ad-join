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

import base64
import datetime
import flask
import os
import logging
import uuid
import string
import time

import google.cloud.kms_v1
import google.auth
import googleapiclient.discovery

import gcp.auth
import gcp.project
import ad.domain
import kerberos.password

# Silence "file_cache" warnings
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
logging.getLogger().setLevel(logging.INFO)

REQUIRED_SCOPRES = ["https://www.googleapis.com/auth/compute.readonly"]
MAX_NETBIOS_COMPUTER_NAME_LENTH = 15
PASSWORD_RESET_RETRIES = 8

#------------------------------------------------------------------------------
# Utility functions.
#------------------------------------------------------------------------------

class ConfigurationException(Exception):
    pass

def __read_required_setting(key):
    if not key in os.environ:
        logging.fatal("%s not defined in environment" % key)
        raise ConfigurationException("Incomplete configuration, see logs")
    else:
        return os.environ[key]

def __read_ad_password():
    if "AD_PASSWORD" in os.environ:
        # Cleartext password provided (useful for testing).
        return os.environ["AD_PASSWORD"]
    else:
        # Decrypt password cipher using the Cloud KMS key provided.
        return google.cloud.kms_v1.KeyManagementServiceClient().decrypt(
            __read_required_setting("CLOUDKMS_KEY"),
            base64.b64decode(__read_required_setting("AD_PASSWORD_CIPHER"))).plaintext.decode("utf-8").strip()

def __connect_to_activedirectory():
    domain = __read_required_setting("AD_DOMAIN")

    if "AD_DOMAINCONTROLLER" in os.environ:
        # Use explicitly defined DC.
        domain_controllers = [os.environ["AD_DOMAINCONTROLLER"]]
    else:
        # Look up DC in DNS.
        domain_controllers = ad.domain.ActiveDirectoryConnection.locate_domain_controllers(
            domain)

    # If we used SRV records to look up domain controllers, then it is possible that
    # the highest-priority one is offline. So loop over the records to fine one
    # that wprks.
    for dc in domain_controllers:
        try:
            return ad.domain.ActiveDirectoryConnection.connect(
                    dc,
                    ",".join(["DC=" + dc for dc in domain.split(".")]),
                    __read_required_setting("AD_USERNAME"),
                    __read_ad_password())
        except Exception as e:
            logging.exception("Failed to connect to DC '%s'" % dc)

    raise ad.domain.LdapException("No more DCs left to try")

def __generate_password(length=40):
    return str(uuid.uuid4()) + "-" + str(uuid.uuid4())

#------------------------------------------------------------------------------
# HTTP endpoints.
#------------------------------------------------------------------------------

HTTP_BAD_METHOD = 405
HTTP_AUTHENTICATION_REQUIRED = 401
HTTP_ACCESS_DENIED = 403
HTTP_CONFLICT = 409
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_BAD_GATEWAY = 502

def __serve_join_script(request):
    """
    Return the PowerShell script to be run on the joining computer. The script
    does not contain any information about the AD domain or infrastructure so that
    it is safe to provide it without authentication.
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "join.ps1"), 'r') as file:
        join_script = file.read().replace(
            "%domain%",
            request.host)

        return flask.Response(join_script, mimetype='text/plain')

def __register_computer(request):
    """
        Create a computer account for the joining computer.
    """

    # Only accept requests with an Authorization header.
    headerName = "Authorization"
    if not headerName in request.headers:
        logging.exception("Authentication missing")
        return flask.abort(HTTP_AUTHENTICATION_REQUIRED)

    # Authenticate the request.
    # Expect the host as audience so that multiple deployments of this
    # services properly reject tokens issued for other deployments.
    try:
        auth_info = gcp.auth.AuthenticationInfo.from_authorization_header(
            request.headers[headerName],
            "https://%s/" % request.host)
    except gcp.auth.AuthorizationException as e:
        logging.exception("Authentication failed")
        return flask.abort(HTTP_ACCESS_DENIED)

    # Connect to Active Directory so that we can authorize the request.
    try:
        ad_connection = __connect_to_activedirectory()
    except Exception as e:
        logging.exception("Connecting to Active Directory failed")
        return flask.abort(HTTP_BAD_GATEWAY)

    # Authorize the request. This entails two checks:
    # (1) Check that AD allows the project to join machines. This is to prevent
    #     rogue/unauthorized projects from joining machines.
    # (2) Check that the project allows AD to manage computer accounts for it.
    #     This is to prevent users from joining machines without the project
    #     owner authorizing it.

    # Authorize, Part 1: Check that there is a OU with the same name as the
    # # project id. The existence of such a OU implies that the owner of the
    # domain is OK with joining machines from that project.
    try:
        matches = ad_connection.find_ou(__read_required_setting("PROJECTS_DN"), auth_info.get_project_id())
        if len(matches) == 0:
            logging.error("No OU with name '%s' found in directory" % auth_info.get_project_id())
            return flask.abort(HTTP_ACCESS_DENIED)
        elif len(matches) > 1:
            logging.error("Found multiple OUs with name '%s' in directory" % auth_info.get_project_id())
            return flask.abort(HTTP_ACCESS_DENIED)
        else:
            # There is an OU. That means the request is fine and we also know which
            # OU to create a computer account in.

            computer_ou = matches[0].get_dn()
            logging.info("Found OU '%s' to create computer account in, authorized (1/2)" % computer_ou)
    except Exception as e:
        logging.exception("Looking up OU '%s' in Active Directory failed" % auth_info.get_project_id())
        return flask.abort(HTTP_INTERNAL_SERVER_ERROR)

    # Authorize, Part 2: Check that we have read access to the project's VM.
    # Read access implies that a project owner or security admin of the project
    # is OK with us managing computer accounts for the project's machines.
    #
    # Access is also required to scavenge stale computer accounts - checking it now
    # reduces the risk of us not being able to scavenge later because of lacking
    # permissions.
    try:
        gce_client = googleapiclient.discovery.build('compute', 'v1')
        gce_instance = gce_client.instances().get(
            project=auth_info.get_project_id(),
            zone=auth_info.get_zone(),
            instance=auth_info.get_instance_name()).execute()

        # Read the hostname, it might be different from the instance name.
        if "hostname" in gce_instance:
            computer_name = gce_instance["hostname"]
            if "." in computer_name:
                computer_name = computer_name.split(".")[0] # Strip domain
        else:
            computer_name = auth_info.get_instance_name()

        logging.info("Successfully read GCE instance data for '%s' (hostname: '%s'), authorized (2/2)" %
            (auth_info.get_instance_name(), computer_name))
    except Exception as e:
        logging.exception("Checking project access to '%s' failed" % auth_info.get_project_id())
        return flask.abort(HTTP_ACCESS_DENIED)

    if len(computer_name) > MAX_NETBIOS_COMPUTER_NAME_LENTH:
        logging.warning("Computer name %s exceeds maximum length for NetBIOS computer names, joining is likely going to fail")

    # The request is now properly authorized, so we are all set to create
    # a computer account in the domain.
    domain = __read_required_setting("AD_DOMAIN")
    try:
        computer_upn = "%s$@%s" % (computer_name, domain)

        # Create computer and add metadata to trace its connection to the
        # GCE VM instance. We also add a temporary UPN to the computer
        # so that we can reset its password via Kerberos.
        computer_account_dn = ad_connection.add_computer(
            computer_ou,
            computer_name,
            computer_upn,
            auth_info.get_project_id(),
            auth_info.get_zone(),
            auth_info.get_instance_name())

        # Assign a random password via Kerberos. Using Kerberos instead of
        # LDAP avoids having to use Secure LDAP.
        kerberos_client = kerberos.password.KerberosPasswordClient(
            domain,
            ad_connection.get_domain_controller(),
            ad_connection.get_domain_controller(),
            ad_connection.get_upn_by_samaccountname(ad_connection.get_user()),
            __read_ad_password())

        set_password_attempt = 0
        while True:
            set_password_attempt += 1
            try:
                computer_password = __generate_password()
                kerberos_client.set_password(
                    computer_upn,
                    computer_password)
                break

            except kerberos.password.KerberosException as e:
                if set_password_attempt <= PASSWORD_RESET_RETRIES:
                    # Setting the password might fail, so try again using a new password.
                    logging.warning("Setting password for '%s' failed (attempt #%d), retrying with different password" % (computer_upn, set_password_attempt))
                    time.sleep(1)

                else:
                    # Give up
                    raise e

        # Remove the temporary UPN.
        ad_connection.remove_computer_upn(computer_ou, computer_name)

        logging.info("Created computer account '%s'" % (computer_account_dn))
    except ad.domain.AlreadyExistsException as e:
        logging.error("Account '%s' already exists" % computer_name)
        return flask.abort(HTTP_CONFLICT)
    except Exception as e:
        logging.exception("Creating computer account for '%s' in '%s' failed" %
            (computer_name, computer_ou))
        return flask.abort(HTTP_INTERNAL_SERVER_ERROR)

    # Return credemtials so that the computer can use them to join.
    return flask.jsonify(
        ComputerName=computer_name,
        ComputerPassword=computer_password,
        OrgUnitPath=computer_ou,
        Domain=domain,
        DomainController=ad_connection.get_domain_controller())

def __cleanup_computers(request):
    """
        Clean up stale computer accounts.
    """

    # Only accept requests with an Authorization header.
    headerName = "Authorization"
    if not headerName in request.headers:
        logging.exception("Authentication missing")
        return flask.abort(HTTP_AUTHENTICATION_REQUIRED)

    # Authenticate the request.
    # Expect the host as audience so that multiple deployments of this
    # services properly reject tokens issued for other deployments.
    try:
        auth_info = gcp.auth.AuthenticationInfo.from_authorization_header(
            request.headers[headerName],
            "https://%s/" % request.host,
            False)
    except gcp.auth.AuthorizationException as e:
        logging.exception("Authentication failed")
        return flask.abort(HTTP_ACCESS_DENIED)

    # Authorize the request. The request must be using the same service
    # account as the cloud function in order to be considered legitimate.
    function_identity = __read_required_setting("FUNCTION_IDENTITY")
    if function_identity != auth_info.get_email():
        logging.error("Untrusted caller '%s', expected '%s'" % (auth_info.get_email(), function_identity))
        return flask.abort(HTTP_ACCESS_DENIED)

    # The request is now properly authorized. Identify projects that we can
    # scavenge.
    try:
        ad_connection = __connect_to_activedirectory()
    except Exception as e:
        logging.exception("Connecting to Active Directory failed")
        return flask.abort(HTTP_BAD_GATEWAY)

    # Although we verify that we can access the VM instance's project when a VM
    # is joined, this project access might later be revoked. When checking whether
    # a VM instance still exists, we therefore need to be careful in distinguishing
    # between the cases (1) the VM does not exist and (2) the VM is inaccessible.

    # Iterate over all OUs underneath the projects OU.
    projects_dn = __read_required_setting("PROJECTS_DN")
    result = {}
    for ou in ad_connection.find_ou(projects_dn):
        try:
            project_id = ou.get_name()

            # Look up list of computer acconts and the zones they are located in.
            computer_accounts = ad_connection.find_computer(ou.get_dn())
            zones = set([c.get_zone() for c in computer_accounts if c.get_zone() != None])

            # Try to obtain the full list of instances in this project. This might
            # fail if we have lost access to the project.
            instance_names = gcp.project.Project(project_id).get_instance_names(zones)


            accounts_deleted = 0
            accounts_failed = 0

            logging.info("Checking for stale computer accounts in project '%s'" % project_id)
            for computer in computer_accounts:
                if not computer.get_instance_name():
                    logging.info("Ignoring computer account '%s' as it lacks for GCE annotations" % computer.get_name())

                elif computer.get_instance_name() in instance_names:
                    # VM instance still exists, fine.
                    pass

                elif computer.get_project_id() != project_id:
                    logging.warning("Computer account '%s' is misplaced - located in '%s', but should be in '%s' OU" %
                        (computer.get_name(), project_id, computer.get_project_id()))

                else:
                    logging.info("Computer account '%s' (project '%s') is stale" % (computer.get_name(), project_id))
                    try:
                        ad_connection.delete_computer(computer.get_dn())
                        accounts_deleted += 1

                    except Exception as e:
                        logging.error("Failed to delete stale compute account '%s' (project '%s')" % (computer.get_name(), project_id))
                        accounts_failed += 1

                # Gather metrics for respomse.
                result[project_id] = {
                    "stale_accounts": accounts_deleted + accounts_failed,
                    "accounts_deleted": accounts_deleted,
                    "accounts_failed": accounts_failed
                }

            logging.info("Done checking for stale computer accounts in project "+
                "'%s' - %d accounts deleted, %d failed to be deleted" %
                (project_id, accounts_deleted, accounts_failed))

        except Exception as e:
            # We cannot access this project, ignore.
            logging.warning("Skipping project '%s' as it is inaccessible: %s" % (project_id, str(e)))

    return flask.jsonify(result)

#------------------------------------------------------------------------------
# Bootstrapping
#------------------------------------------------------------------------------

def register_computer(request):
    """
        Cloud Functions entry point.
    """
    if request.path == "/cleanup" and request.method == "POST":
        return __cleanup_computers(request)
    elif request.path == "/" and request.method == "GET":
        return __serve_join_script(request)
    elif request.path == "/" and request.method == "POST":
        return __register_computer(request)
    else:
        return flask.abort(HTTP_BAD_METHOD)


if __name__ == "__main__":
    # Local testing/debugging only. This code is not run in Cloud Functions.
    from flask import Flask, request

    app = Flask(__name__)
    app.debug=False

    @app.route("/", methods=['GET', 'POST'])
    @app.route("/cleanup", methods=['GET', 'POST'])
    def index():
        return register_computer(request)

    app.run()
