variable "aws_region" {
  description = "Region główny infrastruktury TicketDesk (ECS/ALB/VPC)"
  type        = string
  default     = "eu-north-1"
}

variable "domain_name" {
  description = "Publiczna domena aplikacji"
  type        = string
  default     = "ticketdesk.dev"
}

variable "vpc_id" {
  description = "Identyfikator istniejącej sieci ticketdesk-vpc"
  type        = string
}

variable "alb_arn" {
  description = "ARN istniejącego Application Load Balancera (ticketdesk-alb)"
  type        = string
}

variable "alb_dns_name" {
  description = "Nazwa DNS Application Load Balancera (origin dla CloudFront)"
  type        = string
}

variable "alb_https_listener_arn" {
  description = "ARN listenera HTTPS (443) na ticketdesk-alb"
  type        = string
}

variable "cloudfront_acm_certificate_arn" {
  description = "ARN certyfikatu ACM w regionie us-east-1 dla dystrybucji CloudFront"
  type        = string
}

variable "origin_verify_secret" {
  description = "Tajna wartość nagłówka X-Origin-Verify współdzielona między CloudFront a ALB"
  type        = string
  sensitive   = true
}

variable "waf_rate_limit_global" {
  description = "Maksymalna liczba żądań z jednego IP w oknie 5 minut"
  type        = number
  default     = 1000
}

variable "waf_rate_limit_login" {
  description = "Maksymalna liczba żądań do /login z jednego IP w oknie 5 minut"
  type        = number
  default     = 100
}
