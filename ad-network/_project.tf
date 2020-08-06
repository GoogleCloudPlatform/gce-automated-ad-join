terraform {
  backend "gcs" {
    bucket   = "ntdev-ad-1-tfstate"
    prefix   = "terraform/state"
  }
}

locals {
  project_id = "ntdev-ad-1"
}

provider "google" {
  project    = local.project_id
}

