terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

module "nudgepay" {
  source = "./modules/nudgepay"

  aws_region            = var.aws_region
  environment         = var.environment
  container_image_tag  = var.container_image_tag
  desired_count        = var.desired_count
  database_url         = var.database_url
  redis_url            = var.redis_url
  webhook_shared_secret = var.webhook_shared_secret
  managed_secret_refs   = var.managed_secret_refs
  session_https_only    = var.session_https_only
  cluster_arn           = var.cluster_arn
  task_role_arn         = var.task_role_arn
  execution_role_arn    = var.execution_role_arn
  subnet_ids            = var.subnet_ids
  security_group_ids    = var.security_group_ids
  log_group_name        = var.log_group_name
}

variable "aws_region" {}
variable "environment" {}
variable "container_image_tag" {}
variable "desired_count" { default = 2 }
variable "database_url" {}
variable "redis_url" {}
variable "webhook_shared_secret" {}
variable "managed_secret_refs" { type = map(string) }
variable "session_https_only" { type = bool default = true }
variable "cluster_arn" {}
variable "task_role_arn" {}
variable "execution_role_arn" {}
variable "subnet_ids" { type = list(string) }
variable "security_group_ids" { type = list(string) }
variable "log_group_name" { type = string default = "/aws/ecs/nudgepay" }
