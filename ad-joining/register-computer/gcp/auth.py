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

import google.oauth2.id_token
import google.auth.transport.requests

class AuthorizationException(Exception):
    pass

class InvalidIssuerException(AuthorizationException):
    pass

class InvalidTokenException(AuthorizationException):
    pass

class IncompleteTokenException(AuthorizationException):
    pass

class InvalidAuthorizationHeaderException(AuthorizationException):
    pass

class AuthenticationInfo(object):
    def __init__(self, claims):
        self.__claims = claims

    @staticmethod
    def from_authorization_header(header, audience, require_google_claim=True):
        prefix = "Bearer "
        if not header.startswith(prefix):
            raise InvalidAuthorizationHeaderException("Unrecognized Authorization header")

        return AuthenticationInfo.from_idtoken(header[len(prefix):], audience, require_google_claim)

    @staticmethod
    def from_idtoken(idtoken, audience, require_google_claim=True):
        try:
            # Validate that the token...
            # - comes from Google (iss)
            # - is authentic (signature check)
            # - is valid (iat, exp)
            # - is intended for us (aud)
            token_info = google.oauth2.id_token.verify_oauth2_token(
                idtoken,
                google.auth.transport.requests.Request(),
                audience)
        except ValueError as e:
            raise InvalidTokenException(e)

        if token_info["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            raise InvalidIssuerException("Wrong issuer: '%s'" % token_info["iss"])

        if require_google_claim:
            # Expect a "full" token issued for a VM instance as documented here:
            # https://cloud.google.com/compute/docs/instances/verifying-instance-identity#token_format
            if not "google" in token_info:
                raise IncompleteTokenException("Missing extended claims in token")

        return AuthenticationInfo(token_info)

    def get_issuer(self):
        return self.__claims["iss"]

    def get_email(self):
        return self.__claims["email"]

    def get_project_id(self):
        return self.__claims["google"]["compute_engine"]["project_id"]

    def get_instance_name(self):
        return self.__claims["google"]["compute_engine"]["instance_name"]

    def get_zone(self):
        return self.__claims["google"]["compute_engine"]["zone"]
