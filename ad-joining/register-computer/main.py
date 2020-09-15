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

import werkzeug

from hashlib import blake2b

# Silence "file_cache" warnings
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
logging.getLogger().setLevel(logging.INFO)

MAX_NETBIOS_COMPUTER_NAME_LENGTH = 15
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
            name=__read_required_setting("CLOUDKMS_KEY"),
            ciphertext=base64.b64decode(__read_required_setting("AD_PASSWORD_CIPHER"))).plaintext.decode("utf-8").strip()

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
    # that works.
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

def __get_managed_instance_group_for_instance(gce_instance):
    metadata_created_by = None
    if ("metadata" in gce_instance.keys() and "items" in gce_instance["metadata"]):
        metadata_created_by = next((x for x in gce_instance["metadata"]["items"] if x["key"] == "created-by"), None)

    if (metadata_created_by and "instanceGroupManagers" in metadata_created_by["value"]):
        # https://cloud.google.com/compute/docs/instance-groups/getting-info-about-migs#checking_if_a_vm_instance_is_part_of_a_mig
        # The "created-by" metadata value is in the format of either:
        # projects/[number]/zones/[zone]/instanceGroupManagers/[mig-name]
        # or
        # # projects/[number]/regions/[region]/instanceGroupManagers/[mig-name]
        # Return the mig-name, and the region/zone it belongs to
        mig_info = {}
        mig_id_parts = (metadata_created_by["value"]).split('/')
        mig_info["zone"] = mig_id_parts[3] if mig_id_parts[2] == "zones" else None
        mig_info["region"] = mig_id_parts[3] if mig_id_parts[2] == "regions" else None
        mig_info["name"] = mig_id_parts[5]

        return mig_info
    else:
        return

def __is_gke_nodepool_member(gce_instance):
    return ("labels" in gce_instance.keys() and 'goog-gke-node' in gce_instance["labels"])

def __shorten_computer_name(computer_name, gce_instance):
    # We can shorten the name of instances if they are part of a MIG
    if __get_managed_instance_group_for_instance(gce_instance):
        if __is_gke_nodepool_member(gce_instance):
            # For MIGs created by GKE, we will use a special naming convention
            # Generate GKE node naming convention k-XXXXXXXX-YYYY 
            # k - Kubernetes node
            # X - unique value given to the cluster's node pool
            # Y - unique value given to each instance by the MIG
            instance_name_parts = computer_name.rsplit('-', 2)
            node_pool_hash = instance_name_parts[-2]
            unique_id = instance_name_parts[-1]
            new_computer_name = ("k-%s-%s" % (node_pool_hash, unique_id))
        else: 
            # Generate MIG naming convention XXXXX-YYYY-ZZZZ
            # X - partial MIG name
            # Y - hashed value of MIG name
            # Z - unique value given to each instance by the MIG
            instance_name_parts = computer_name.rsplit('-', 1)
            mig_name = instance_name_parts[-2]
            unique_id = instance_name_parts[-1]
            # Create a hash that produces 4 hex characters
            hasher = blake2b(digest_size=2)
            hasher.update(mig_name.encode("utf-8"))
            mig_name_hash = hasher.hexdigest()
            # Get first 5 characters from MIG's name
            mig_name_prefix = mig_name[:5]
            new_computer_name = ("%s-%s-%s" % (mig_name_prefix, mig_name_hash, unique_id))        
    else:        
        # Not MIG - create a name using the convention XXXXXXXXXX-YYYY
        # X - partial instance name
        # Y - hashed value of instance name
        hasher = blake2b(digest_size=3)
        hasher.update(computer_name.encode("utf-8"))
        instance_name_hash = hasher.hexdigest()
        instance_name_prefix = computer_name[:10]
        new_computer_name = ("%s-%s" % (instance_name_prefix, instance_name_hash))
    return new_computer_name

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
    
    original_computer_name = computer_name

    if len(computer_name) > MAX_NETBIOS_COMPUTER_NAME_LENGTH:
        # Try to shorten the computer name
        computer_name = __shorten_computer_name(computer_name, gce_instance)
        logging.info("Computer name was shortened from %s to %s" % (original_computer_name, computer_name))

    # The request is now properly authorized, so we are all set to create
    # a computer account in the domain.
    domain = __read_required_setting("AD_DOMAIN")
    
    try:
        computer_upn = "%s$@%s" % (computer_name, domain)

        # Create computer and add metadata to trace its connection to the
        # GCE VM instance. We also add a temporary UPN to the computer
        # so that we can reset its password via Kerberos.
        try:
            computer_account_dn = ad_connection.add_computer(
                computer_ou,
                computer_name,
                computer_upn,
                auth_info.get_project_id(),
                auth_info.get_zone(),
                auth_info.get_instance_name())
            
            new_computer_account = True

        except ad.domain.AlreadyExistsException:
            # Computer already exists. If this is the same instance and project name
            # then assume this is a re-imaged VM, and continue
            computer_account_dn = ("CN=%s,%s" % (computer_name, computer_ou))
            try:
                computer_accounts = ad_connection.find_computer(computer_account_dn)

                computer_account = computer_accounts[0]
                # Validate this is the same project, instance name, and zone
                is_same_computer = (computer_account.get_instance_name() == auth_info.get_instance_name() 
                    and computer_account.get_project_id() == auth_info.get_project_id())

                if is_same_computer:
                    # Account found in AD is in the same project and has 
                    # the same name as the given instance so we can reuse it
                    logging.info("Account '%s' already exists, reusing" % computer_name)
                    # We need to add a temporary UPN to the computer
                    # so that we can reset its password via Kerberos
                    ad_connection.set_computer_upn(computer_ou, computer_name, computer_upn)

                    if (computer_account.get_zone() != auth_info.get_zone()):
                        # The instance we have was created in a different zone
                        # than then AD account. We need to update the zone attribute.
                        logging.info("Account '%s' is listed in a different zone (%s). Updating to zone %s" 
                            % (computer_name, computer_account.get_zone(), auth_info.get_zone()))
                        ad_connection.set_computer_zone(computer_ou, computer_name, auth_info.get_zone())
                    
                    new_computer_account = False
                else:
                    logging.error("Account '%s' already exists in the project, but has different attributes" % (computer_name))
                    flask.abort(HTTP_CONFLICT)
            except ad.domain.NoSuchObjectException as e:
                logging.error("Account '%s' already exists, but cannot be found in project '%s'. It probably belongs to a different project." % 
                    (computer_name, auth_info.get_project_id()))
                flask.abort(HTTP_CONFLICT)

        # Check if the instance is part of a Managed Instance Group (MIG)
        mig_info = __get_managed_instance_group_for_instance(gce_instance)
        mig_name = mig_info.get("name") if mig_info else None

        # New instances of MIGs are added to AD groups named after the MIGs.
        # Having an AD group with the MIG's computers is useful for managing
        # Access control in the domain
        if new_computer_account and mig_name:            
            # Add the computer to an AD group containing all the MIG's computers
            # This is only relevant to newly added computers
            # as previously added computers were already added to the group
            logging.info("Instance '%s' is part of Managed Instance Group '%s'. Account will be added to a matching group" 
                % (auth_info.get_instance_name(), mig_name))

            # Find if the MIG already has an AD group
            mig_dn = ("CN=%s,%s" % (mig_name, computer_ou))
            try:
                mig_ad_group = ad_connection.find_group(mig_dn)

                logging.info("AD Group '%s' found. Adding computer '%s' to the group"
                    %(mig_name, auth_info.get_instance_name()))
            except ad.domain.NoSuchObjectException as e:
                # Group does not exists, create it.
                try:
                    logging.info("AD Group '%s' not found. Attempting to create it" % (mig_name))
                    ad_connection.add_group(computer_ou, mig_name, auth_info.get_project_id(), mig_info["zone"], mig_info["region"])
                except ad.domain.AlreadyExistsException:
                    # Two options why group already exists:
                    # 1. Group was just created by a parallel process adding another computer from the same MIG
                    # 2. Group by this name already exists in a different project
                    mig_ad_group = ad_connection.find_group(mig_dn)
                    if len(mig_ad_group) == 0:
                        logging.error("Failed adding AD Group for MIG '%s' in project '%s'. There is probably a MIG by this name in another OU" 
                            % (mig_name, auth_info.get_project_id()))
                        flask.abort(HTTP_CONFLICT)
                    else: 
                        # Group added in the same project, safe to proceed
                        logging.info("AD Group '%s' found while creating. Assuming it was added by another computer joining in parallel" % (mig_name))                

            # Add the computer account to group
            ad_connection.add_member_to_group(computer_ou, mig_name, computer_account_dn)

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
                    logging.warning("Setting password for '%s' failed (attempt #%d), retrying with different password" % 
                        (computer_upn, set_password_attempt))
                    time.sleep(1)

                else:
                    # Give up
                    raise e

        # Remove the temporary UPN.
        ad_connection.remove_computer_upn(computer_ou, computer_name)

        logging.info("Created computer account '%s'" % (computer_account_dn))
    except werkzeug.exceptions.Conflict as e:
        # Re-throw HTTP 409 (Conflict) that is used throughout this try/except, 
        # to avoid it being replaced by the HTTP 500 for general exceptions 
        raise e
    except Exception as e:
        logging.exception("Creating computer account for '%s' in '%s' failed" %
            (computer_name, computer_ou))
        return flask.abort(HTTP_INTERNAL_SERVER_ERROR)

    # Return credentials so that the computer can use them to join.
    return flask.jsonify(
        OriginalComputerName=original_computer_name,
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
            output = {
                "computers" : {},
                "groups" : {}
            }
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

            # Gather metrics for response.
            output["computers"] = {
                "stale_accounts": accounts_deleted + accounts_failed,
                "accounts_deleted": accounts_deleted,
                "accounts_failed": accounts_failed
            }

            logging.info("Done checking for stale computer accounts in project "+
                "'%s' - %d accounts deleted, %d failed to be deleted" %
                (project_id, accounts_deleted, accounts_failed))

            # After deleting stale computers, look for empty groups.
            # Empty group means either its MIG has no computers (scaled to 0), 
            # or the MIG was deleted
            mig_ad_groups = ad_connection.find_group(ou.get_dn())            
            zones = set([g.get_zone() for g in mig_ad_groups if g.get_zone() != None])
            regions = set([g.get_region() for g in mig_ad_groups if g.get_region() != None])
            mig_names = gcp.project.Project(project_id).get_managed_instance_group_names(zones, regions)

            accounts_deleted = 0
            accounts_failed = 0
            logging.info("Checking for stale managed instance groups in project '%s'" % project_id)
            for mig_ad_group in mig_ad_groups:                
                if not mig_ad_group.get_project_id():
                    logging.info("Ignoring group '%s' as it lacks for GCE annotations" % mig_ad_group.get_name())

                elif mig_ad_group.get_name() in mig_names:
                    # MIG still exists, fine.
                    pass

                elif mig_ad_group.get_project_id() != project_id:
                    logging.warning("Group '%s' is misplaced - located in '%s', but should be in '%s' OU" %
                        (mig_ad_group.get_name(), project_id, mig_ad_group.get_project_id()))

                else:
                    logging.info("Group '%s' (project '%s') is stale" % (mig_ad_group.get_name(), project_id))
                    try:
                        ad_connection.delete_group(mig_ad_group.get_dn())
                        accounts_deleted += 1

                    except Exception as e:
                        logging.error("Failed to delete stale group '%s' (project '%s')" % (mig_ad_group.get_name(), project_id))
                        accounts_failed += 1

            # Gather metrics for response.
            output["groups"] = {
                "stale_accounts": accounts_deleted + accounts_failed,
                "accounts_deleted": accounts_deleted,
                "accounts_failed": accounts_failed
            }

            result[project_id] = output
            logging.info("Done checking for stale groups in project "+
                "'%s' - %d group deleted, %d failed to be deleted" %
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
