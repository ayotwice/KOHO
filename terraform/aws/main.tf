# PCI-DSS Compliance Infrastructure
terraform {
  required_version = ">= 1.0"
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

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# VPC and Network Security (Controls 1.1, 1.2, 1.3)
resource "aws_vpc" "pci_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "pci-compliant-vpc"
    Environment = var.environment
    Compliance  = "PCI-DSS"
    Controls    = "1.1,1.2,1.3"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "pci_igw" {
  vpc_id = aws_vpc.pci_vpc.id

  tags = {
    Name = "pci-igw"
  }
}

# Public Subnet (DMZ)
resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.pci_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "pci-public-${count.index + 1}"
    Type = "DMZ"
  }
}

# Private Subnet (Cardholder Data Environment)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.pci_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "pci-private-${count.index + 1}"
    Type = "CDE"
  }
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.pci_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.pci_igw.id
  }

  tags = {
    Name = "pci-public-rt"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.pci_vpc.id

  tags = {
    Name = "pci-private-rt"
  }
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Security Groups (Control 1.1)
resource "aws_security_group" "web_tier" {
  name_prefix = "pci-web-"
  vpc_id      = aws_vpc.pci_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name     = "pci-web-sg"
    Controls = "1.1"
  }
}

resource "aws_security_group" "app_tier" {
  name_prefix = "pci-app-"
  vpc_id      = aws_vpc.pci_vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier.id]
  }

  tags = {
    Name     = "pci-app-sg"
    Controls = "1.1,1.2"
  }
}

resource "aws_security_group" "db_tier" {
  name_prefix = "pci-db-"
  vpc_id      = aws_vpc.pci_vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
  }

  tags = {
    Name     = "pci-db-sg"
    Controls = "1.1,1.2,7.1"
  }
}

# KMS Key for Encryption (Controls 3.4, 3.6)
resource "aws_kms_key" "pci_key" {
  description             = "PCI-DSS compliant encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name     = "pci-encryption-key"
    Controls = "3.4,3.6"
  }
}

resource "aws_kms_alias" "pci_key_alias" {
  name          = "alias/pci-compliance-key"
  target_key_id = aws_kms_key.pci_key.key_id
}

# RDS Instance with Encryption (Control 3.4)
resource "aws_db_subnet_group" "pci_db_subnet_group" {
  name       = "pci-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "pci-db-subnet-group"
  }
}

resource "aws_db_instance" "pci_database" {
  identifier = "pci-compliant-db"

  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp2"
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.pci_key.arn

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  vpc_security_group_ids = [aws_security_group.db_tier.id]
  db_subnet_group_name   = aws_db_subnet_group.pci_db_subnet_group.name

  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  enabled_cloudwatch_logs_exports = ["error", "general", "slow_query"]

  skip_final_snapshot = true

  tags = {
    Name     = "pci-database"
    Controls = "3.4,10.1,10.2"
  }
}

# S3 Bucket with Encryption (Control 3.4)
resource "aws_s3_bucket" "pci_data" {
  bucket = "${var.environment}-pci-data-${random_id.bucket_suffix.hex}"

  tags = {
    Name     = "pci-data-bucket"
    Controls = "3.4"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_encryption" "pci_data_encryption" {
  bucket = aws_s3_bucket.pci_data.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.pci_key.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_versioning" "pci_data_versioning" {
  bucket = aws_s3_bucket.pci_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "pci_data_pab" {
  bucket = aws_s3_bucket.pci_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM Roles and Policies (Controls 7.1, 7.2)
resource "aws_iam_role" "pci_app_role" {
  name = "pci-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Controls = "7.1,7.2"
  }
}

resource "aws_iam_policy" "pci_app_policy" {
  name = "pci-app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.pci_data.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.pci_key.arn
      }
    ]
  })

  tags = {
    Controls = "7.1,7.2"
  }
}

resource "aws_iam_role_policy_attachment" "pci_app_policy_attachment" {
  role       = aws_iam_role.pci_app_role.name
  policy_arn = aws_iam_policy.pci_app_policy.arn
}

# CloudTrail for Logging (Controls 10.1, 10.2)
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.environment}-pci-cloudtrail-${random_id.cloudtrail_suffix.hex}"

  tags = {
    Name     = "pci-cloudtrail-logs"
    Controls = "10.1,10.2"
  }
}

resource "random_id" "cloudtrail_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_encryption" "cloudtrail_encryption" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.pci_key.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_pab" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "pci_trail" {
  name           = "pci-compliance-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.bucket
  s3_key_prefix  = "cloudtrail"

  kms_key_id = aws_kms_key.pci_key.arn

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.pci_data.arn}/*"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]

  tags = {
    Name     = "pci-cloudtrail"
    Controls = "10.1,10.2"
  }
}

# Application Load Balancer with SSL (Control 4.1)
resource "aws_lb" "pci_alb" {
  name               = "pci-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web_tier.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false

  tags = {
    Name     = "pci-alb"
    Controls = "4.1"
  }
}

# SSL Certificate
resource "aws_acm_certificate" "pci_cert" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name     = "pci-ssl-cert"
    Controls = "4.1"
  }
}

resource "aws_lb_listener" "pci_https" {
  load_balancer_arn = aws_lb.pci_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.pci_cert.arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "PCI Compliant Application"
      status_code  = "200"
    }
  }

  tags = {
    Controls = "4.1"
  }
}

# System Configuration - Launch Template (Control 2.2)
resource "aws_launch_template" "pci_template" {
  name_prefix   = "pci-template-"
  image_id      = var.ami_id
  instance_type = "t3.micro"

  vpc_security_group_ids = [aws_security_group.app_tier.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.pci_profile.name
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    region = var.aws_region
  }))

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 20
      volume_type = "gp3"
      encrypted   = true
      kms_key_id  = aws_kms_key.pci_key.arn
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name     = "pci-instance"
      Controls = "2.2,3.4"
    }
  }

  tags = {
    Name     = "pci-launch-template"
    Controls = "2.2"
  }
}

resource "aws_iam_instance_profile" "pci_profile" {
  name = "pci-instance-profile"
  role = aws_iam_role.pci_app_role.name
}