terraform {
  backend "s3" {
    bucket         = "terraform-state-geekyrbhalala"
    key            = "root-account-activity-monitoring/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
  }
}