terraform {
  backend "gcs" {
    bucket   = "ntdev-ad-8-tfstate"
    prefix   = "terraform/ad-forest"
  }
}

locals {
  project_id = "ntdev-ad-8"
}

provider "google" {
  project    = local.project_id
}