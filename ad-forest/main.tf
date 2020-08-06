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

#------------------------------------------------------------------------------
# Mandatory input variables
#------------------------------------------------------------------------------

variable "admin_password" {
    description = "Directory services restore mode password"
    type = string
}

#------------------------------------------------------------------------------
# Optional input variables
#------------------------------------------------------------------------------


variable "vpchost_project_id" {
    description = "Shared VPC Host Project ID"
    type = string
    default = null
}

variable "region" {
    description = "Region to deploy in"
    type = string
    default = "us-central1"
}

variable "subnet" {
    description = "Subnet name"
    type = string
    default = "default"
}

variable "image_family" {
    description = "Image family to use for domain controllers"
    type = string
    default = "windows-cloud/windows-2019-core"
}

variable "serviceaccount_name" {
    description = "Service account mame for domain controllers"
    type = string
    default = "ad-domaincontroller"
}

variable "dns_domain" {
    description = "DNS domain name for AD forest root domain"
    type = string
    default = "example.org"
}

variable "netbios_domain" {
    description = "NetBIOS domain name for AD forest root domain"
    type = string
    default = "example"
}

variable "machine_type" {
    description = "Machine type"
    type = string
    default = "n1-standard-2"
}

variable "instance_prefix" {
    description = "Name prefix of VM instance"
    type = string
    default = "dc-"
}

#------------------------------------------------------------------------------
# Local variables
#------------------------------------------------------------------------------

provider "google-beta" {
    project          = local.project_id
    region           = var.region
}

locals {
    dc_count         = 2
    zones            = ["${var.region}-a", "${var.region}-b", "${var.region}-c", "${var.region}-f"]
    secret_expiry    = timeadd(timestamp(), "1h")
}

#------------------------------------------------------------------------------
# Required APIs
#------------------------------------------------------------------------------

resource "google_project_service" "compute" {
    project = local.project_id
    service = "compute.googleapis.com"
}

resource "google_project_service" "secretmanager" {
    project = local.project_id
    service = "secretmanager.googleapis.com"
}

resource "google_project_service" "dns" {
    project = coalesce(var.vpchost_project_id, local.project_id)
    service = "dns.googleapis.com"
}

#------------------------------------------------------------------------------
# Service account for domain controllers
#------------------------------------------------------------------------------
# [START serviceaccount]

resource "google_service_account" "dc" {
    project      = local.project_id
    account_id   = var.serviceaccount_name
    display_name = "AD domain controller"
}

# [END serviceaccount]

#------------------------------------------------------------------------------
# Admin/Directory Services Resource Mode password
#
# The password is stored in Secret Manager and the service account for 
# domain controllers is _temporarily_ granted access to the secret.
#
# NB. Conditions on Secrets are not supported yet, so set
# the binding on the project. 
#------------------------------------------------------------------------------
# [START secret]

resource "google_secret_manager_secret" "dc-dsrm-password" {
    provider    = google-beta
    project      = local.project_id
    depends_on  = [google_project_service.secretmanager]

    secret_id = "dc-dsrm-password"
    replication {
        user_managed {
            replicas {
                location = var.region
            }
        }
    }
}

resource "google_secret_manager_secret_version" "dc-dsrm-password" {
    provider = google-beta
    depends_on  = [google_project_service.secretmanager]
    
    secret = google_secret_manager_secret.dc-dsrm-password.id

    secret_data = var.admin_password
}

resource "google_project_iam_member" "dc-dsrm-password" {
    provider = google-beta
    project      = local.project_id

    role = "roles/secretmanager.secretAccessor"
    member = "serviceAccount:${google_service_account.dc.email}"

    # Grant access for one hour only. Once DCs have been deployed,
    # noone should be allowed to access the secret anymore.
    condition {
        title       = "Expires after 1h"
        expression  = "request.time < timestamp(\"${local.secret_expiry}\")"
    }
}

# [END secret]

#------------------------------------------------------------------------------
# Static IP addresses
#------------------------------------------------------------------------------
# [START addresses]

data "google_compute_subnetwork" "dc_subnet" {
    name   = var.subnet
    region = var.region
    project = coalesce(var.vpchost_project_id, local.project_id)
}

resource "google_compute_address" "dc" {
    provider = google-beta
    project = local.project_id
    depends_on  = [google_project_service.compute]
    
    count        = local.dc_count

    name         = "${var.instance_prefix}${count.index + 1}"
    
    # NB. Avoid using x.x.x.0 and .1 as these are reserved IP addresses
    address      = cidrhost(data.google_compute_subnetwork.dc_subnet.ip_cidr_range, count.index + 2)
    region       = var.region
    subnetwork   = data.google_compute_subnetwork.dc_subnet.self_link
    address_type = "INTERNAL"
}
# [END addresses]

#------------------------------------------------------------------------------
# Private DNS forwarding zone
#------------------------------------------------------------------------------
# [START dns]

resource "google_dns_managed_zone" "dns_zone" {
    provider     = google-beta
    project      = coalesce(var.vpchost_project_id, local.project_id)
    depends_on  = [google_project_service.dns]
    
    name         = replace(var.dns_domain, ".", "-")
    dns_name     = "${var.dns_domain}."
    visibility = "private"
    
    private_visibility_config {
        networks {
            network_url = data.google_compute_subnetwork.dc_subnet.network
        }
    }
    forwarding_config {
        dynamic "target_name_servers" {
            for_each = google_compute_address.dc
            content {
                ipv4_address = target_name_servers.value.address
            }
        }
    }
}

# [END dns]

#------------------------------------------------------------------------------
# Domain controllers
#------------------------------------------------------------------------------
# [START dc]

resource "google_compute_instance" "dc" {
    provider     = google-beta
    project      = local.project_id
    depends_on   = [google_project_service.compute]
    
    count        = local.dc_count

    name         = "${var.instance_prefix}${count.index + 1}"
    machine_type = var.machine_type
    zone         = local.zones[count.index]

    tags = ["ad-domaincontroller"]
  
    boot_disk {
        initialize_params {
            image = var.image_family
        }
    }

    network_interface {
        network     = data.google_compute_subnetwork.dc_subnet.network
        subnetwork  = data.google_compute_subnetwork.dc_subnet.self_link
        network_ip  = google_compute_address.dc[count.index].address
    }

    service_account {
        email = google_service_account.dc.email
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    }

    metadata = {
        VmDnsSetting = "ZonalPreferred"
        ActiveDirectoryDnsDomain = var.dns_domain
        ActiveDirectoryNetbiosDomain = var.netbios_domain

        sysprep-specialize-script-ps1 = <<EOT
            $ErrorActionPreference = "stop"
            Install-WindowsFeature AD-Domain-Services,DNS
        EOT

        windows-startup-script-ps1 = file(count.index == 0 ? "${path.module}/scripts/startup-dc-01.ps1" : "${path.module}/scripts/startup-dc-02.ps1")
    }
}

# [END dc]
