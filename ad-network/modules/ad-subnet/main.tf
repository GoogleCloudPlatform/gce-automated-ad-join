#------------------------------------------------------------------------------
# Input variables
#------------------------------------------------------------------------------

variable "project_id" {
    description = "Project of parent VPC"
    type = string
}

variable "vpc_name" {
    description = "Name of parent VPC"
    type = string
}

variable "region" {
    description = "Region of subnet"
    type = string
}

variable "subnet_name" {
    description = "Name of subnet"
    type = string
}

variable "subnet_cidr_range" {
    description = "CIDR range of this subnet"
    type = string
}

variable "dc_network_tag" {
    description = "Service account email of domain controllers"
    type = string
    default = "ad-domaincontroller"
}

variable "allow_ad_logons" {
    description = "Allow domain logons of users and computers from this subnet"
    type = bool
}

variable "allow_ad_webservices" {
    description = "Allow access to AD web services from this subnet"
    type = bool
}

variable "allow_ad_ldaps" {
    description = "Allow Secure LDAP access from this subnet"
    type = bool
}

variable "allow_ad_replication" {
    description = "Allow replication between domain controllers"
    type = bool
}

variable "allow_rdp_via_iap" {
    description = "Allow RDP access via IAP to VMs in this subnet"
    type = bool
}

variable "allow_clouddns" {
    description = "Allow Cloud DNS ingress"
    type = bool
}

variable "log_failed_accesses" {
    description = "Log all failed access attempts"
    type = bool
}


#------------------------------------------------------------------------------
# Output variables
#------------------------------------------------------------------------------

output "self_link" {
  value = google_compute_subnetwork.dc.self_link 
}

#------------------------------------------------------------------------------
# Local variables
#------------------------------------------------------------------------------

provider "google" {
    project                 = var.project_id
    region                  = var.region
}

locals {
    default_priority        = 10000
    clouddns_cidr           = "35.199.192.0/19"
    iap_cidr                = "35.235.240.0/20"
}

#------------------------------------------------------------------------------
# Subnet
#------------------------------------------------------------------------------

resource "google_compute_subnetwork" "dc" {
  depends_on    = [var.vpc_name]
  name          = var.subnet_name
  project       = var.project_id
  ip_cidr_range = var.subnet_cidr_range
  region        = var.region
  network       = var.vpc_name
  private_ip_google_access  = true
}

#------------------------------------------------------------------------------
# Firewall rules
#------------------------------------------------------------------------------

resource "google_compute_firewall" "allow-rdp-ingress-from-iap" {
  count = var.allow_rdp_via_iap ? 1 : 0
  
  name       = "${var.subnet_name}-allow-rdp-ingress-from-iap"
  project    = var.project_id
  network    = var.vpc_name
  priority   = local.default_priority
  direction  = "INGRESS"
             
  source_ranges = [ local.iap_cidr ]

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}

resource "google_compute_firewall" "allow-logon-ingress-to-addc" {
  count = var.allow_ad_logons ? 1 : 0
  
  name       = "${var.subnet_name}-allow-logon-ingress-to-addc"
  project    = var.project_id
  network    = var.vpc_name
  priority   = local.default_priority
  direction  = "INGRESS"
  
  source_ranges = [ var.subnet_cidr_range ]
  target_tags   = [ var.dc_network_tag ]

  allow {
    protocol = "tcp"
    ports    = ["53", "88", "135", "389", "445", "464", "3268", "49152-65535"]
  }
  
  allow {
    protocol = "udp"
    ports    = ["53", "88", "123", "389", "445", "464", "3268"]
  }
}

resource "google_compute_firewall" "allow-adws-ingress-to-addc" {
  count = var.allow_ad_webservices ? 1 : 0
  
  name       = "${var.subnet_name}-allow-adws-ingress-to-addc"
  project    = var.project_id
  network    = var.vpc_name
  priority   = local.default_priority
  direction  = "INGRESS"
  
  source_ranges = [ var.subnet_cidr_range ]
  target_tags   = [ var.dc_network_tag ]

  allow {
    protocol = "tcp"
    ports    = ["9389"]
  }
}

resource "google_compute_firewall" "allow-ldaps-ingress-to-addc" {
  count = var.allow_ad_ldaps ? 1 : 0
  
  name       = "${var.subnet_name}-allow-ldaps-ingress-to-addc"
  project    = var.project_id
  network    = var.vpc_name
  priority   = local.default_priority
  direction  = "INGRESS"
  
  source_ranges = [ var.subnet_cidr_range ]
  target_tags   = [ var.dc_network_tag ]

  allow {
    protocol = "tcp"
    ports    = ["9389"]
  }
}

resource "google_compute_firewall" "allow-replication-ingress-to-addc" {
  count = var.allow_ad_replication ? 1 : 0
  
  name      = "${var.subnet_name}-allow-replication-ingress-to-addc"
  project   = var.project_id
  network    = var.vpc_name
  priority  = local.default_priority
  direction = "INGRESS"
  
  source_tags   = [ var.dc_network_tag ]
  target_tags   = [ var.dc_network_tag ]

  allow {
    protocol = "tcp"
    ports    = ["53", "88", "135", "389", "445", "49152-65535"]
  }
  
  allow {
    protocol = "udp"
    ports    = ["53", "88", "123", "389", "445"]
  }
}

resource "google_compute_firewall" "allow-clouddns-ingress-to-addc" {
  count = var.allow_clouddns ? 1 : 0
  
  name    = "${var.subnet_name}-allow-dns-ingress-from-clouddns"
  project = var.project_id
  network    = var.vpc_name
  priority = local.default_priority
  direction = "INGRESS"
  
  source_ranges = [ local.clouddns_cidr ]
  target_tags   = [ var.dc_network_tag ]

  allow {
    protocol = "tcp"
    ports    = ["53"]
  }
  
  allow {
    protocol = "udp"
    ports    = ["53"]
  }
}

resource "google_compute_firewall" "deny-ingress-from-all" {
  count = var.log_failed_accesses ? 1 : 0
  
  name      = "${var.subnet_name}-deny-ingress-from-all"
  project   = var.project_id
  network    = var.vpc_name
  priority  = 65000
  direction = "INGRESS"
  enable_logging = true
  
  deny {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  deny {
    protocol = "udp"
    ports    = ["0-65535"]
  }
}