#
# Copyright 2020 Google LLC
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

FROM gcc:latest as build-cc
ADD /ksetpwd /ksetpwd
RUN cd /ksetpwd && make ksetpwd

FROM python:3.10-slim

ENV SERVER_WORKERS=3

ADD /register-computer /register-computer
RUN groupadd -r runner && \
    useradd -rm -g runner runner && \
    mkdir -p /register-computer/kerberos/bin && \
    apt-get update && \
    apt-get install -y libkrb5-3 && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install -r /register-computer/requirements.txt --no-cache-dir
COPY --from=build-cc /ksetpwd/ksetpwd /register-computer/kerberos/bin
COPY --from=build-cc /lib/x86_64-linux-gnu/libcom_err.* /register-computer/kerberos/bin/
RUN chown -R runner /register-computer && \
    chmod ugo+r -R /register-computer/*

USER runner
WORKDIR /register-computer

CMD exec gunicorn --bind :$PORT --workers $SERVER_WORKERS --timeout 0 main:app
