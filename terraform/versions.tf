terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.region
  # TF-3: an empty-string profile makes some AWS SDK versions look for a
  # literally-named "" profile instead of falling back to the default
  # credential chain. Map "" -> null so empty truly means "use the default
  # chain" (env vars, SSO, instance role).
  profile = var.aws_profile != "" ? var.aws_profile : null
  default_tags {
    tags = {
      Project   = "cost-events-to-teams"
      ManagedBy = "terraform"
      Owner     = var.owner
    }
  }
}
