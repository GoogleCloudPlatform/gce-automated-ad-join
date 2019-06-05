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

import googleapiclient.discovery

class Project(object):
    def __init__(self, project_id):
        self.__project_id = project_id
        self.__gce_client = googleapiclient.discovery.build('compute', 'v1')

    def get_zones(self):
        page_token = None
        zones = []

        while True:
            result = self.__gce_client.zones().list(
                project=self.__project_id,
                pageToken=page_token).execute()
            zones += [item["name"] for item in result["items"]]

            if not page_token:
                break

        return zones

    def get_instance_names(self, zones):
        page_token = None
        names = []

        for zone in zones:
            while True:
                result = self.__gce_client.instances().list(
                    project=self.__project_id,
                    zone=zone,
                    pageToken=page_token).execute()
                if "items" in result:
                    names += [item["name"] for item in result["items"]]

                if not page_token:
                    break

        return names
