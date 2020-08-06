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
# Optional input variables
#------------------------------------------------------------------------------

variable "region" {
    description = "Region to deploy in"
    type = string
    default = "us-central1"
}

variable "enable_shared_vpc" {
    description = "Allow VPC to be shared"
    type = bool
    default = true
}

variable "vpc_name" {
    description = "Name of VPC"
    type = string
    default = "ad"
}

variable "dc_subnet_cidr" {
    description = "Subnet CIDR for domain controllers (size /29 min)"
    type = string
    default = "192.168.0.0/28"
}

variable "management_subnet_cidr" {
    description = "Subnet CIDR for AD management VMs (size /29 min)"
    type = string
    default = "192.168.0.16/28"
}

variable "resources_subnet_cidr" {
    description = "Subnet CIDR for resource servers (size /29 min)"
    type = string
    default = "192.168.1.0/24"
}

variable "dc_network_tag" {
    description = "Service account email of domain controllers"
    type = string
    default = "ad-domaincontroller"
}

#------------------------------------------------------------------------------
# Required APIs
#------------------------------------------------------------------------------

resource "google_project_service" "compute" {
    project = local.project_id
    service = "compute.googleapis.com"
    disable_on_destroy = false
}

#------------------------------------------------------------------------------
# VPC
#------------------------------------------------------------------------------
# [START vpc]

resource "google_compute_network" "vpc" {
  depends_on           = [google_project_service.compute]
  
  name      = var.vpc_name
  project   = local.project_id
  auto_create_subnetworks = false
}

resource "google_compute_shared_vpc_host_project" "host" {
  depends_on           = [google_compute_network.vpc]
  
  count = var.enable_shared_vpc ? 1 : 0
  project =         local.project_id
}

# [END vpc]
#------------------------------------------------------------------------------
# Subnets
#------------------------------------------------------------------------------
# [START subnets]

module "dc-subnet" {
    source                 = "./modules/ad-subnet"
    project_id                = local.project_id
    region                 = var.region

    vpc_name                 = google_compute_network.vpc.self_link
    subnet_name            = "domain-controllers"
    subnet_cidr_range      = var.dc_subnet_cidr
                        
    log_failed_accesses    = true
    allow_ad_replication   = true
    allow_clouddns         = true
    allow_ad_logons        = false
    allow_ad_webservices   = false
    allow_ad_ldaps         = false
    allow_rdp_via_iap      = true
}

module "management-subnet" {
    source                 = "./modules/ad-subnet"
    project_id                = local.project_id
    region                 = var.region

    vpc_name                 = google_compute_network.vpc.self_link
    subnet_name            = "management"
    subnet_cidr_range      = var.management_subnet_cidr
                           
    log_failed_accesses    = true
    allow_ad_replication   = false
    allow_clouddns         = false
    allow_ad_logons        = true
    allow_ad_webservices   = true
    allow_ad_ldaps         = true
    allow_rdp_via_iap      = true
}

module "resources-subnet" {
    source                 = "./modules/ad-subnet"
    project_id                = local.project_id
    region                 = var.region

    vpc_name                 = google_compute_network.vpc.self_link
    subnet_name            = "resources"
    subnet_cidr_range      = var.resources_subnet_cidr
                           
    log_failed_accesses    = false
    allow_ad_replication   = false
    allow_clouddns         = false
    allow_ad_logons        = true
    allow_ad_webservices   = false
    allow_ad_ldaps         = true
    allow_rdp_via_iap      = true
}

# [END subnets]