terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# CloudFront i WAF o zasięgu CLOUDFRONT wymagają zasobów w regionie us-east-1
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# ==============================================================================
# 1. AWS WAF v2 (Ochrona L7: OWASP Core, SQLi, Known Bad Inputs, AntyDDoS Rate)
# ==============================================================================
resource "aws_wafv2_web_acl" "ticketdesk_edge" {
  provider    = aws.us_east_1
  name        = "ticketdesk-edge-waf"
  description = "WAF dla dystrybucji CloudFront systemu TicketDesk (LAB7)"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Reguła 1: Ochrona /login przed brute-force i credential stuffing (L7)
  rule {
    name     = "RateLimitLogin"
    priority = 10
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit_login
        aggregate_key_type = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string         = "/login"
            positional_constraint = "STARTS_WITH"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "TicketDeskRateLimitLogin"
      sampled_requests_enabled   = true
    }
  }

  # Reguła 2: Globalny limit zapytań na IP (AntyDDoS L7)
  rule {
    name     = "RateLimitGlobal"
    priority = 20
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit_global
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "TicketDeskRateLimitGlobal"
      sampled_requests_enabled   = true
    }
  }

  # Reguła 3: Reputacja adresów IP Amazon (botnety, znane źródła ataków)
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 30
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "TicketDeskIpReputation"
      sampled_requests_enabled   = true
    }
  }

  # Reguła 4: Zestaw OWASP Core (XSS, LFI, RFI, manipulacje nagłówków)
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 40
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "TicketDeskCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Reguła 5: Znane złośliwe wektory (Log4Shell, SSRF, eksploitacja nagłówków)
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 50
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "TicketDeskKnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  # Reguła 6: Ochrona przed SQL Injection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 60
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "TicketDeskSQLi"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "TicketDeskEdgeWAF"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudwatch_log_group" "waf_logs" {
  provider          = aws.us_east_1
  name              = "aws-waf-logs-ticketdesk"
  retention_in_days = 30
}

resource "aws_wafv2_web_acl_logging_configuration" "ticketdesk_edge" {
  provider                = aws.us_east_1
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]
  resource_arn            = aws_wafv2_web_acl.ticketdesk_edge.arn
}

# ==============================================================================
# 2. Amazon CloudFront (CDN + AWS Shield Standard L3/L4 AntyDDoS)
# ==============================================================================
data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

resource "aws_cloudfront_distribution" "ticketdesk" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "TicketDesk CDN + WAF + Shield Standard (LAB7)"
  aliases         = [var.domain_name]
  web_acl_id      = aws_wafv2_web_acl.ticketdesk_edge.arn
  price_class     = "PriceClass_100"

  origin {
    domain_name = var.alb_dns_name
    origin_id   = "ticketdesk-alb-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "X-Origin-Verify"
      value = var.origin_verify_secret
    }
  }

  # Dynamiczne widoki aplikacji: brak cache'owania, przekazywanie ciasteczek i nagłówków
  default_cache_behavior {
    target_origin_id         = "ticketdesk-alb-origin"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods           = ["GET", "HEAD"]
    compress                 = true
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id
  }

  # Zasoby statyczne (/static/*): buforowanie na krawędzi CDN
  ordered_cache_behavior {
    path_pattern           = "/static/*"
    target_origin_id       = "ticketdesk-alb-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    cache_policy_id        = data.aws_cloudfront_cache_policy.caching_optimized.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.cloudfront_acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# Blokada bezpośredniego ruchu do ALB (omijającego CloudFront i WAF)
resource "aws_lb_listener_rule" "block_without_origin_header" {
  listener_arn = var.alb_https_listener_arn
  priority     = 1

  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Forbidden"
      status_code  = "403"
    }
  }

  condition {
    http_header {
      http_header_name = "X-Origin-Verify"
      values           = [var.origin_verify_secret]
    }
  }
}

# ==============================================================================
# 3. IPS/IDS: Amazon GuardDuty + VPC Flow Logs + Alarmy CloudWatch
# ==============================================================================
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
  }
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/ticketdesk-flow-logs"
  retention_in_days = 30
}

resource "aws_iam_role" "vpc_flow_logs" {
  name = "ticketdesk-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "vpc-flow-logs.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "ticketdesk-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
      }
    ]
  })
}

resource "aws_flow_log" "ticketdesk_vpc" {
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = var.vpc_id
}

resource "aws_cloudwatch_metric_alarm" "waf_blocked_spike" {
  provider            = aws.us_east_1
  alarm_name          = "ticketdesk-waf-blocked-requests-spike"
  alarm_description   = "Alert przy gwałtownym wzroście żądań blokowanych przez WAF (możliwy atak DDoS/skanowanie)"
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 100
  comparison_operator = "GreaterThanOrEqualToThreshold"

  dimensions = {
    WebACL = aws_wafv2_web_acl.ticketdesk_edge.name
    Region = "global"
    Rule   = "ALL"
  }
}
