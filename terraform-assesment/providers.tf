variable "region" {
description = "AWS region for hosting our your network"
default = "ap-south-1"
}

provider "aws" {
  region                  = "ap-south-1"
  access_key = "xxxxxxxxxxxx"
  secret_key = "xxxxxxxxxxx"
}
