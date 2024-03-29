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

import os
import subprocess
import logging
import tempfile

class KerberosException(Exception):
    def __init__(self, message, error_code):
        self.__message = message
        self.__error_code = error_code
        super().__init__(self.__message)

    def get_error_code(self):
        return self.__error_code

class KerberosPasswordClient(object):
    KSETPWD_BINARY = "ksetpwd"

    def __init__(self, realm, kdc, admin_server, client_upn, client_password):
        self.__realm = realm
        self.__kdc = kdc
        self.__admin_server = admin_server
        self.__client_upn = client_upn
        self.__client_password = client_password

    def __generate_config_file(self):
        config = """[libdefaults]
dns_lookup_realm = false
dns_lookup_kdc = false

[realms]
%s = {
    kdc = %s
    admin_server = %s
}
""" % (self.__realm.upper(), self.__kdc, self.__admin_server)

        handle, name = tempfile.mkstemp(prefix = "krb5.")
        with open(handle, "w", encoding = "utf-8") as f:
            f.write(config)

        return name

    def set_password(self, upn, password):
        bin_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "bin")

        config_file = self.__generate_config_file()

        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = bin_path          # for libcom_err.so
        env["KRB5_CONFIG"] = config_file
        env["KSETPWD_AGENT_PASSWORD"] = self.__client_password
        env["KSETPWD_TARGET_PASSWORD"] = password

        ksetpwd = os.path.join(bin_path, KerberosPasswordClient.KSETPWD_BINARY)

        logging.info("Launching %s with environment config at %s and admin server %s" % (ksetpwd, config_file, self.__admin_server))

        # NB. Realm names must be upper case to work.
        process = subprocess.run(
            [ksetpwd, self.__client_upn.upper(), upn.upper()],
            capture_output=True,
            env=env)

        # Delete KRB5 config
        os.unlink(config_file)

        if process.returncode == 0:
            if process.stderr:
                logging.info(process.stderr)
            if process.stdout:
                logging.info(process.stdout)
        else:
            if process.stderr:
                logging.warning(process.stderr)
            if process.stdout:
                logging.warning(process.stdout)

            raise KerberosException("Password reset failed: %d" % process.returncode, process.returncode)
