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

AD_PASSWORD_CIPHER := $(shell echo $(AD_PASSWORD) | gcloud kms encrypt \
  --ciphertext-file=- \
  --plaintext-file=- \
  --key=computer-registrar-key \
  --keyring=computer-registrar-keyring \
  --location=global \
  --version=1 \
  --project=$(DOMAIN_PROJECT_ID) \
| base64 --wrap=0)

COMPUTER_REGISTRAR_KEY_ID := "projects/$(DOMAIN_PROJECT_ID)/locations/global/keyRings/computer-registrar-keyring/cryptoKeys/computer-registrar-key"

default: deploy

prerequisites:
	sudo apt-get install libkrb5-dev -y

ksetpwd: prerequisites
	make -C ksetpwd

deploy: ksetpwd
	gcloud functions deploy register-computer \
	  --entry-point=register_computer \
	  --runtime=python37 \
	  --trigger-http \
      --allow-unauthenticated \
	  --source=register-computer \
	  --service-account=$(REGISTRAR_EMAIL) \
	  --project=$(DOMAIN_PROJECT_ID) \
	  --region=$(SERVERLESS_REGION) \
	  --vpc-connector=projects/$(DOMAIN_PROJECT_ID)/locations/$(SERVERLESS_REGION)/connectors/serverless-connector \
--set-env-vars="^;^AD_DOMAIN=$(AD_DOMAIN);AD_USERNAME=$(AD_NETBIOS_DOMAIN)\\CompRegistrar;AD_PASSWORD_CIPHER=$(AD_PASSWORD_CIPHER);CLOUDKMS_KEY=$(COMPUTER_REGISTRAR_KEY_ID);PROJECTS_DN=$(PROJECTS_DN)"
