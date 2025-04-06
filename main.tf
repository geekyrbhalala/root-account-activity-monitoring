variable "aws_region" {}
variable "root_account_monitoring_trail" {}
variable "cloudtrail_log_bucket_name" {}
variable "log_group_name" {}
variable "alert_email" {}

locals {

  cloudwatch_log_metric_filter_name = "RootAccountUsage"
  cloudwatch_log_namespace = "CloudTrailMetrics"
  cloudwatch_alarm_name = "RootAccountUsageAlarm"
  sns_topic_name = "RootAccountUsageAlarm"
}

data "aws_caller_identity" "current" {}

###############################################
#  PROVIDER SETUP
###############################################

provider "aws" {
  region = var.aws_region  # Set the AWS region from a variable
}

# Create CloudWatch Logs Log Group
resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name              = var.log_group_name
  retention_in_days = 7
}

# IAM Role for CloudTrail to send logs to CloudWatch
resource "aws_iam_role" "cloudtrail_role" {
  name = "CloudTrailToCloudWatchRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
    }]
  })
}

# IAM Policy for logging to CloudWatch
resource "aws_iam_role_policy" "cloudtrail_policy" {
  name = "cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "logs:PutLogEvents",
          "logs:CreateLogStream"
        ],
        Resource = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
      },
      {
        Effect   = "Allow",
        Action   = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ],
        Resource = "*"
      }
    ]
  })
}

###############################################
#  CREATE LOGGING BUCKET FOR CLOUDTRAIL
###############################################

# Separate bucket to store CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_log_bucket" {
  bucket = var.cloudtrail_log_bucket_name
  force_destroy = true

  tags = {
    Name = var.cloudtrail_log_bucket_name
  }
}

# Restrict public access to the log bucket for security
resource "aws_s3_bucket_public_access_block" "log-bucket-acl" {
  bucket = aws_s3_bucket.cloudtrail_log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy allowing CloudTrail to write logs to the logging bucket
resource "aws_s3_bucket_policy" "cloudtrail_log_policy" {
  bucket = aws_s3_bucket.cloudtrail_log_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid: "AWSCloudTrailWrite",
        Effect: "Allow",
        Principal: {
          Service: "cloudtrail.amazonaws.com"
        },
        Action: "s3:PutObject",
        Resource: "${aws_s3_bucket.cloudtrail_log_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition: {
          StringEquals: {
            "s3:x-amz-acl": "bucket-owner-full-control"
          }
        }
      },
      {
        Sid: "AWSCloudTrailBucketPermissionsCheck",
        Effect: "Allow",
        Principal: {
          Service: "cloudtrail.amazonaws.com"
        },
        Action: "s3:GetBucketAcl",
        Resource: aws_s3_bucket.cloudtrail_log_bucket.arn
      }
    ]
  })
}

###############################################
#  ENABLE CLOUDTRAIL FOR S3 MONITORING
###############################################

# CloudTrail setup to track root acocunt activity
resource "aws_cloudtrail" "root_account_trail" {
  name                          = var.root_account_monitoring_trail
  s3_bucket_name                = aws_s3_bucket.cloudtrail_log_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_role.arn
}

# CloudWatch Metric Filter for Root Account Usage
resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  name           = local.cloudwatch_log_metric_filter_name
  log_group_name = aws_cloudwatch_log_group.cloudtrail_log_group.name
  pattern        = "{ $.userIdentity.type = \"Root\" }"
  metric_transformation {
    name      = local.cloudwatch_log_metric_filter_name
    namespace = local.cloudwatch_log_namespace
    value     = "1"
  }
}

###############################################
#  CREATE SNS TOPIC & EMAIL SUBSCRIPTION
###############################################

resource "aws_sns_topic" "root_account_activity_alerts" {
  name = local.sns_topic_name
}

# Email subscriber to receive alerts
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.root_account_activity_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "root_account_usage_alarm" {
  alarm_name                = local.cloudwatch_alarm_name
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = local.cloudwatch_log_metric_filter_name
  namespace                 = local.cloudwatch_log_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Alarm when the Root user is used in the last 5 minutes"
  treat_missing_data        = "notBreaching"
  alarm_actions             = [aws_sns_topic.root_account_activity_alerts.arn]
}

