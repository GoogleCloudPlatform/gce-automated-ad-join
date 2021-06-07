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

import google.auth
import googleapiclient.discovery
from google.cloud import secretmanager

import gcp.auth
import gcp.project
import ad.domain
import kerberos.password

import werkzeug

from hashlib import blake2b
from flask import Flask, request

# Silence "file_cache" warnings
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
logging_level = os.getenv("LOGGING_LEVEL", logging.INFO)
logging.getLogger().setLevel(logging_level)

MAX_NETBIOS_COMPUTER_NAME_LENGTH = 15
PASSWORD_RESET_RETRIES = 10

#------------------------------------------------------------------------------
# Utility functions.
#------------------------------------------------------------------------------

class ConfigurationException(Exception):
    pass

def __get_request_scheme(request):
    return request.headers.get("X-Forwarded-Proto", request.scheme)

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
        client = secretmanager.SecretManagerServiceClient()
        
        # If the Service Account does not have permissions
        # to access the secret an Exception will be raised
        try:        
            name = client.secret_version_path(
                    __read_required_setting("SECRET_PROJECT_ID"), 
                    __read_required_setting("SECRET_NAME"), 
                    __read_required_setting("SECRET_VERSION"))
            response = client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
        except Exception as e:
            # If neither AD_PASSWORD nor Secret Manager hold the password rethrow exception
            logging.exception("Could not retrieve secret from Secret Manager: %s" % e)
            raise e

def __connect_to_activedirectory(ad_site):
    domain = __read_required_setting("AD_DOMAIN")

    if "AD_DOMAINCONTROLLER" in os.environ:
        # Use explicitly defined DC.
        domain_controllers = [os.environ["AD_DOMAINCONTROLLER"]]
    else:
        # Look up DC in DNS.
        domain_controllers = ad.domain.ActiveDirectoryConnection.locate_domain_controllers(
            domain, ad_site)

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
    return

def __is_gke_nodepool_member(gce_instance):
    return ("labels" in gce_instance.keys() and 'goog-gke-node' in gce_instance["labels"])

def __shorten_computer_name(computer_name, gce_instance):
    # Initialize hasher with a 2-byte size
    hasher = blake2b(digest_size=2)

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
            hasher.update(mig_name.encode("utf-8"))
            mig_name_hash = hasher.hexdigest()

            # Get first 5 characters from MIG's name
            mig_name_prefix = mig_name[:5]
            new_computer_name = ("%s-%s-%s" % (mig_name_prefix, mig_name_hash, unique_id))        
    else:        
        # Not MIG - create a name using the convention XXXXXXXXXX-YYYY
        # X - partial instance name
        # Y - hashed value of instance name
        hasher.update(computer_name.encode("utf-8"))
        instance_name_hash = hasher.hexdigest()
        instance_name_prefix = computer_name[:10]
        new_computer_name = ("%s-%s" % (instance_name_prefix, instance_name_hash))
        
    return new_computer_name

def __get_computer_ou_from_metadata(gce_instance):
    gce_instance_name = gce_instance["name"]
    logging.debug("Checking instance '%s' for target OU in metadata", gce_instance_name)

    if ("metadata" in gce_instance.keys() and "items" in gce_instance["metadata"]):
        target_ou = next((x for x in gce_instance["metadata"]["items"] if x["key"].lower() == "target_ou"), None)
        if target_ou:
            return target_ou["value"]
        else:
            logging.info("Instance '%s' metadata is missing a custom OU" % gce_instance_name)
    else:
        logging.info("Instance '%s' does not have metadata" % gce_instance_name)
    
    return

def __is_custom_ou_valid(ad_connection, custom_ou_dn):
    try:
        matches = ad_connection.find_ou(custom_ou_dn, includeDescendants=False)
        if len(matches) == 0:
            logging.info("No OU with name '%s' found in directory" % custom_ou_dn)
        elif len(matches) > 1:
            logging.info("Found multiple OUs with name '%s' in directory" % custom_ou_dn)
        else:
            return True
    except Exception as e:
        logging.exception("Looking up OU '%s' in Active Directory failed: '%s'" % (custom_ou_dn, str(e)))
        raise

    return False

def __get_custom_ou_for_computer(ad_connection, gce_instance, instance_name, project_id):
    computer_ou = None
    # The service is configured to use custom OUs. Make sure the root OU is valid
    custom_ou_root = __read_required_setting("CUSTOM_OU_ROOT_DN")
    logging.debug("Service is configured to use custom OU root '%s'" % custom_ou_root)
    if __is_custom_ou_valid(ad_connection, custom_ou_root):
        # Locate the custom OU for the computer and make sure it is valid
        custom_target_ou = __get_computer_ou_from_metadata(gce_instance)
        if custom_target_ou and __is_custom_ou_valid(ad_connection, custom_target_ou):
            logging.debug("Found custom OU '%s' for compute instance '%s' in project '%s'" 
                % (custom_target_ou, instance_name, project_id))

            # Verify the OU provided for the computer is a descendant of the custom root OU
            if custom_target_ou.lower().endswith(custom_ou_root.lower()):
                computer_ou = custom_target_ou
            else:
                logging.error("The OU '%s' provided by the computer instance '%s' is not a descendant of the root OU '%s'" 
                    % (custom_target_ou, instance_name, custom_ou_root))
        else:
            logging.error("The OU '%s' provided by the computer instance '%s' is either missing or not valid" 
                % (custom_target_ou, instance_name))
    else:
        logging.error("Custom OU root '%s' is not valid" % custom_ou_root)
    
    return computer_ou

#------------------------------------------------------------------------------
# HTTP endpoints.
#------------------------------------------------------------------------------

HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_BAD_METHOD = 405
HTTP_AUTHENTICATION_REQUIRED = 401
HTTP_ACCESS_DENIED = 403
HTTP_CONFLICT = 409
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_BAD_GATEWAY = 502

def __serve_join_script(request, ad_domain):
    """
    Return the PowerShell script to be run on the joining computer. The script
    does not contain any information about the AD domain or infrastructure so that
    it is safe to provide it without authentication.
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "join.ps1"), 'r') as file:
        join_script = file.read()
        join_script = join_script.replace("%domain%", request.host)
        join_script = join_script.replace("%scheme%", __get_request_scheme(request))
        join_script = join_script.replace("%ad_domain%", ad_domain)

        return flask.Response(join_script, mimetype='text/plain')

def __register_computer(request):
    """
        Create a computer account for the joining computer.
    """    
   
    # Only accept requests with an Authorization header.
    headerName = "Authorization"
    if not headerName in request.headers:
        logging.exception("Authentication missing")
        return flask.abort(HTTP_AUTHENTICATION_REQUIRED, description="CALLER_AUTHENTICATION_MISSING")

    # Authenticate the request.
    # Expect the host as audience so that multiple deployments of this
    # services properly reject tokens issued for other deployments.
    try:
        auth_info = gcp.auth.AuthenticationInfo.from_authorization_header(
            request.headers[headerName],
            "%s://%s/" % (__get_request_scheme(request), request.host))
    except gcp.auth.AuthorizationException as e:
        logging.exception("Authentication failed")
        return flask.abort(HTTP_ACCESS_DENIED, description="CALLER_AUTHENTICATION_FAILED")

    # Connect to Active Directory so that we can authorize the request.
    try:
        ad_site = request.args.get("ad_site")
        ad_connection = __connect_to_activedirectory(ad_site)
    except Exception as e:
        logging.exception("Connecting to Active Directory failed")
        return flask.abort(HTTP_BAD_GATEWAY, description="CONNECT_TO_AD_FAILED")

    # Authorize the request. This entails two checks:
    # (1) Check that the project allows AD to manage computer accounts for it.
    #     This is to prevent users from joining machines without the project
    #     owner authorizing it.
    # (2) Check that AD allows the project to join machines. This is to prevent
    #     rogue/unauthorized projects from joining machines.

    # Authorize, Part 1: Check that we have read access to the project's VM.
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

        logging.info("Successfully read GCE instance data for '%s' (hostname: '%s'), authorized (1/2)" %
            (auth_info.get_instance_name(), computer_name))
    except Exception as e:
        logging.exception("Checking project access to '%s' failed" % auth_info.get_project_id())
        return flask.abort(HTTP_ACCESS_DENIED, description="PROJECT_ACCESS_FAILED")

    # Authorize, Part 2: Check that there is a OU with the same name as the
    # project id. The existence of such a OU implies that the owner of the
    # domain is OK with joining machines from that project.
    # This check is ignored if the service is configured to use a custom OU.
    # For custom OU, users will need to use an external way to make sure rogue/unauthorized
    # projects cannot access the service, for example, by using a Shared VPC with Service projects.
    computer_ou = None
    if "PROJECTS_DN" in os.environ and "CUSTOM_OU_ROOT_DN" in os.environ:
        logging.error("Cannot have both PROJECTS_DN and CUSTOM_OU_ROOT_DN environment variables configured. Please make sure only one is present.")
        return flask.abort(HTTP_CONFLICT, description="BAD_ROOT_OU_CONFIGURATION")
    elif "PROJECTS_DN" in os.environ:
        try:
            matches = ad_connection.find_ou(__read_required_setting("PROJECTS_DN"), auth_info.get_project_id())
            if len(matches) == 0:
                logging.error("No OU with name '%s' found in directory" % auth_info.get_project_id())
                return flask.abort(HTTP_ACCESS_DENIED, description="MISSING_PROJECT_OU")
            elif len(matches) > 1:
                logging.error("Found multiple OUs with name '%s' in directory" % auth_info.get_project_id())
                return flask.abort(HTTP_ACCESS_DENIED, description="MULTIPLE_PROJECT_OUS")
            else:
                # There is an OU. That means the request is fine and we also know which
                # OU to create a computer account in.
                project_ou = matches[0].get_dn()                
                logging.info("Found OU '%s', authorized (2/2)" % project_ou)
                logging.info("Computer will be created in a project OU: '%s'" % project_ou)
                computer_ou = project_ou
        except Exception as e:
            logging.exception("Looking up OU '%s' in Active Directory failed" % auth_info.get_project_id())
            return flask.abort(HTTP_INTERNAL_SERVER_ERROR, description="PROJECT_OU_UNKNOWN_ERROR")
    # If custom OU is being used, then extract it from the compute instance
    elif "CUSTOM_OU_ROOT_DN" in os.environ:
        try:
            custom_ou = __get_custom_ou_for_computer(ad_connection, gce_instance, auth_info.get_instance_name(), auth_info.get_project_id())
            if not custom_ou:
                return flask.abort(HTTP_BAD_REQUEST, description="BAD_CUSTOM_OU")

            logging.info("Found the OU '%s' that is a descendant of the custom root OU, authorized (2/2)" % custom_ou)
            logging.info("Computer will be created in a custom OU: '%s'" % custom_ou)
            computer_ou = custom_ou
        except Exception:
            return flask.abort(HTTP_INTERNAL_SERVER_ERROR, description="UNKNOWN_CUSTOM_OU_ERROR")
    else:
        logging.error("Could not find PROJECTS_DN nor CUSTOM_OU_ROOT_DN in the environment variables. Failed to configure OU root.")
        return flask.abort(HTTP_INTERNAL_SERVER_ERROR, description="BAD_ROOT_OU_CONFIGURATION")

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
                # Validate this is the same project and instance name
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
                    logging.error("Account '%s' already exists in OU '%s' with different attributes. Current attributes are (instance='%s', project='%s'), and requested attributes are (instance='%s', project='%s')" 
                        % (computer_name, computer_ou, computer_account.get_instance_name(), computer_account.get_project_id(), auth_info.get_instance_name(), auth_info.get_project_id()))
                    flask.abort(HTTP_CONFLICT, description="SIMILAR_COMPUTER_ACCOUNT_EXISTS_IN_AD")
            except ad.domain.NoSuchObjectException as e:
                logging.error("Account '%s' from project '%s' already exists, but cannot be found in OU '%s'. It probably belongs to a different project or is configured to use a different OU" % 
                    (computer_name, auth_info.get_project_id(), computer_ou))
                flask.abort(HTTP_CONFLICT, description="SIMILAR_COMPUTER_ACCOUNT_EXISTS_IN_AD")

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
                        # This error should raise a flag, as AD creates each group with a unique SAM account name, therefore
                        # we shouldn't get groups with the same ID in other OUs.
                        logging.error("Failed adding AD Group for MIG '%s' in project '%s'. There is probably a MIG by this name in another OU" 
                            % (mig_name, auth_info.get_project_id()))
                        flask.abort(HTTP_CONFLICT, "GROUP_ALREADY_EXISTS_IN_AD")
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
                if e.get_error_code() == 1:
                    # Error is related to the agent (AD user). No point trying again
                    logging.error("Setting password for '%s' failed. Unrecoverable error" % (computer_upn))
                    raise e 
                if set_password_attempt <= PASSWORD_RESET_RETRIES:
                    # Setting the password might fail, so try again using a new password.
                    # Password setting is sent by AD to all DCs. Failure can occur in AD 
                    # with multiple DCs, if replication did not yet happen, and some DCs 
                    # are not aware to the new computer account.                    
                    logging.warning("Setting password for '%s' failed (attempt #%d), retrying with different password" % 
                        (computer_upn, set_password_attempt))
                    time.sleep(2)
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
        return flask.abort(HTTP_INTERNAL_SERVER_ERROR, description="UNKNOWN_ERROR_CREATE_COMPUTER_ACCOUNT")

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
        return flask.abort(HTTP_AUTHENTICATION_REQUIRED, description="CALLER_AUTHENTICATION_MISSING")

    # Authenticate the request.
    # Expect the host as audience so that multiple deployments of this
    # services properly reject tokens issued for other deployments.
    try:
        auth_info = gcp.auth.AuthenticationInfo.from_authorization_header(
            request.headers[headerName],
            "%s://%s/" % (__get_request_scheme(request), request.host),
            False)
    except gcp.auth.AuthorizationException as e:
        logging.exception("Authentication failed")
        return flask.abort(HTTP_ACCESS_DENIED, description="CALLER_AUTHENTICATION_FAILED")

    # Authorize the request. The request must be using the same service
    # account as the cloud function in order to be considered legitimate.
    function_identity = __read_required_setting("FUNCTION_IDENTITY")
    if function_identity != auth_info.get_email():
        logging.error("Untrusted caller '%s', expected '%s'" % (auth_info.get_email(), function_identity))
        return flask.abort(HTTP_ACCESS_DENIED, description="CALLER_AUTHENTICATION_FAILED")

    # The request is now properly authorized. Identify projects that we can
    # scavenge.
    try:
        ad_connection = __connect_to_activedirectory()
    except Exception as e:
        logging.exception("Connecting to Active Directory failed")
        return flask.abort(HTTP_BAD_GATEWAY, description="CONNECT_TO_AD_FAILED")

    # Although we verify that we can access the VM instance's project when a VM
    # is joined, this project access might later be revoked. When checking whether
    # a VM instance still exists, we therefore need to be careful in distinguishing
    # between the cases (1) the VM does not exist and (2) the VM is inaccessible.

    # Iterate over all OUs underneath the projects OU or the custom OU, if specified
    projects_root_dn = os.getenv("PROJECTS_DN")
    root_dn = os.getenv("CUSTOM_OU_ROOT_DN", projects_root_dn)
    
    if not root_dn or root_dn == "":
        logging.warning("Cleanup cannot start. Could not find root OU to start the scan from.")
        return flask.abort(HTTP_INTERNAL_SERVER_ERROR, description="BAD_ROOT_OU_CONFIGURATION")

    logging.info("Starting cleanup in OU '%s'" % root_dn)
    result = {}
    for ou in ad_connection.find_ou(root_dn):
        try:            
            ou_name = ou.get_dn()
            # Look up list of computer accounts in the OU
            computer_accounts = ad_connection.find_computer(ou.get_dn())

            output = {
                "computers" : {},
                "groups" : {}
            }
            accounts_deleted = 0
            accounts_failed = 0

            logging.info("Checking for stale computer accounts in OU '%s'" % ou_name)
            for computer in computer_accounts:
                if not computer.get_instance_name() or not computer.get_project_id() or not computer.get_project_id():
                    logging.debug("Ignoring computer account '%s' as it lacks for GCE annotations" % computer.get_name())

                elif gcp.project.Project(computer.get_project_id()).get_instance(computer.get_instance_name(), computer.get_zone()):
                    # VM instance still exists, fine.
                    logging.debug("Skipping computer account '%s' as it has a matching instance '%s' in project '%s'" 
                        % (computer.get_name(), computer.get_instance_name(), computer.get_project_id()))
                    pass
                else:
                    logging.info("Computer account '%s' (instance '%s' in project '%s') is stale" 
                        % (computer.get_name(), computer.get_instance_name(), computer.get_project_id()))
                    try:
                        ad_connection.delete_computer(computer.get_dn())
                        accounts_deleted += 1

                    except Exception as e:
                        logging.error("Failed to delete stale compute account '%s' (instance '%s' in project '%s')" 
                            % (computer.get_name(), computer.get_instance_name(), computer.get_project_id()))
                        accounts_failed += 1

            # Gather metrics for response.
            output["computers"] = {
                "stale_accounts": accounts_deleted + accounts_failed,
                "accounts_deleted": accounts_deleted,
                "accounts_failed": accounts_failed
            }

            logging.info("Done checking for stale computer accounts in OU "+
                "'%s' - %d accounts deleted, %d failed to be deleted" %
                (ou_name, accounts_deleted, accounts_failed))

            # After deleting stale computers, look for groups whose MIGs were removed
            mig_ad_groups = ad_connection.find_group(ou.get_dn())
            accounts_deleted = 0
            accounts_failed = 0
            logging.info("Checking for stale managed instance groups in OU '%s'" % ou_name)
            for mig_ad_group in mig_ad_groups:                
                if not mig_ad_group.get_project_id() or (not mig_ad_group.get_zone() and not mig_ad_group.get_region()):
                    logging.debug("Ignoring group '%s' as it lacks for GCE annotations" % mig_ad_group.get_name())

                elif gcp.project.Project(mig_ad_group.get_project_id()).get_managed_instance_group(mig_ad_group.get_name(), mig_ad_group.get_zone(), mig_ad_group.get_region()):
                    # MIG still exists, fine.
                    logging.debug("Skipping group '%s' as it has a matching managed instance group in project '%s'" 
                        % (mig_ad_group.get_name(), mig_ad_group.get_project_id()))
                    pass
                else:
                    logging.info("Group '%s' (project '%s') is stale" % (mig_ad_group.get_name(), mig_ad_group.get_project_id()))
                    try:
                        ad_connection.delete_group(mig_ad_group.get_dn())
                        accounts_deleted += 1

                    except Exception as e:
                        logging.error("Failed to delete stale group '%s' (project '%s')" % (mig_ad_group.get_name(), mig_ad_group.get_project_id()))
                        accounts_failed += 1

            # Gather metrics for response.
            output["groups"] = {
                "stale_accounts": accounts_deleted + accounts_failed,
                "accounts_deleted": accounts_deleted,
                "accounts_failed": accounts_failed
            }

            result[ou_name] = output
            logging.info("Done checking for stale groups in OU "+
                "'%s' - %d group deleted, %d failed to be deleted" %
                (ou_name, accounts_deleted, accounts_failed))
        except Exception as e:
            # We cannot access this project, ignore.
            logging.warning("Skipping OU '%s' as it is inaccessible: %s" % (ou_name, str(e)))

    return flask.jsonify(result)

#------------------------------------------------------------------------------
# Bootstrapping
#------------------------------------------------------------------------------

def register_computer(request):
    """
        Cloud Functions entry point.
    """
    if request.path == "/hc" and request.method == "GET":
        # Health Check
        return flask.Response(status=HTTP_OK)
    elif request.path == "/cleanup" and request.method == "POST":
        return __cleanup_computers(request)
    elif request.path == "/" and request.method == "GET":
        return __serve_join_script(request, __read_required_setting("AD_DOMAIN"))
    elif request.path == "/" and request.method == "POST":
        return __register_computer(request)
    else:
        return flask.abort(HTTP_BAD_METHOD)

app = Flask(__name__)
app.debug = False

@app.route("/", methods=['GET', 'POST'])
@app.route("/cleanup", methods=['GET', 'POST'])
@app.route("/hc", methods=['GET'])

def index():
    return register_computer(request)

def _handle_http_exception(e):
    return flask.jsonify(error=e.description), e.code

for code in werkzeug.exceptions.default_exceptions:
    app.register_error_handler(code, _handle_http_exception)

if __name__ == "__main__":
    app.run()

