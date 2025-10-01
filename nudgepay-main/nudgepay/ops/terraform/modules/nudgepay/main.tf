terraform {
  required_version = ">= 1.6.0"
}

variable "aws_region" {
  type = string
}

variable "environment" {
  type = string
}

variable "container_image_tag" {
  type = string
}

variable "desired_count" {
  type    = number
  default = 2
}

variable "database_url" {
  type = string
  validation {
    condition     = can(regex("^postgres(ql)?://", var.database_url))
    error_message = "database_url must use a postgres scheme"
  }
}

variable "redis_url" {
  type = string
}

variable "webhook_shared_secret" {
  type = string
}

variable "managed_secret_refs" {
  type = map(string)
  validation {
    condition     = alltrue([for v in values(var.managed_secret_refs) : can(regex("^(aws-secrets|vault|gcp-sm|env)://", v))])
    error_message = "All managed_secret_refs must reference a supported provider"
  }
}

variable "session_https_only" {
  type    = bool
  default = true
}

variable "cluster_arn" {
  type = string
}

variable "task_role_arn" {
  type = string
}

variable "execution_role_arn" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "security_group_ids" {
  type = list(string)
}

variable "log_group_name" {
  type    = string
  default = "/aws/ecs/nudgepay"
}

locals {
  container_environment = [
    {
      name  = "DATABASE_URL"
      value = var.database_url
    },
    {
      name  = "REDIS_URL"
      value = var.redis_url
    },
    {
      name  = "SESSION_HTTPS_ONLY"
      value = var.session_https_only ? "true" : "false"
    },
    {
      name  = "AUTOMATION_SCHEDULER_TARGET"
      value = "terraform"
    }
  ]

  container_secrets = [
    for key, ref in var.managed_secret_refs : {
      name      = key
      valueFrom = ref
    }
  ]
}

resource "aws_cloudwatch_log_group" "this" {
  name              = var.log_group_name
  retention_in_days = 30
}

resource "aws_ecs_task_definition" "this" {
  family                   = "nudgepay-${var.environment}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = "nudgepay"
      image     = "public.ecr.aws/nudgepay/app:${var.container_image_tag}"
      essential = true
      portMappings = [{
        containerPort = 8000
        hostPort      = 8000
        protocol      = "tcp"
      }]
      environment      = local.container_environment
      secrets          = local.container_secrets
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "this" {
  name            = "nudgepay-${var.environment}"
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.subnet_ids
    security_groups = var.security_group_ids
    assign_public_ip = true
  }
}

output "service_name" {
  value = aws_ecs_service.this.name
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.this.arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}
