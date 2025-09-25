# Configure the AWS Provider
terraform {
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

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

# Get the latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Generate a random string for unique naming
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Create a VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "main-vpc-${random_string.suffix.result}"
  }
}

# Create an Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "main-igw-${random_string.suffix.result}"
  }
}

# Create a subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-${random_string.suffix.result}"
  }
}

# Get available AZs
data "aws_availability_zones" "available" {
  state = "available"
}

# Create a route table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "public-rt-${random_string.suffix.result}"
  }
}

# Associate the route table with the subnet
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Create a security group
resource "aws_security_group" "web" {
  name_prefix = "web-sg-"
  description = "Security group for web server"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
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
    Name = "web-sg-${random_string.suffix.result}"
  }
}

# Create a key pair using tls_private_key
resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "deployer" {
  key_name   = "deployer-key-${random_string.suffix.result}"
  public_key = tls_private_key.example.public_key_openssh
}

# Save the private key locally (optional)
resource "local_file" "private_key" {
  content  = tls_private_key.example.private_key_pem
  filename = "deployer-key-${random_string.suffix.result}.pem"
  file_permission = "0600"
}

# Create an S3 bucket for application logs
resource "aws_s3_bucket" "app_logs" {
  bucket = "app-logs-${random_string.suffix.result}"

  tags = {
    Name        = "Application Logs"
    Environment = "dev"
  }
}

# S3 bucket versioning
resource "aws_s3_bucket_versioning" "app_logs_versioning" {
  bucket = aws_s3_bucket.app_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 bucket server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "app_logs_encryption" {
  bucket = aws_s3_bucket.app_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Create an IAM role for EC2 to access S3
resource "aws_iam_role" "ec2_s3_role" {
  name = "ec2-s3-role-${random_string.suffix.result}"

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
}

# IAM policy for S3 access
resource "aws_iam_role_policy" "ec2_s3_policy" {
  name = "ec2-s3-policy-${random_string.suffix.result}"
  role = aws_iam_role.ec2_s3_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.app_logs.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.app_logs.arn
      }
    ]
  })
}

# Instance profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-profile-${random_string.suffix.result}"
  role = aws_iam_role.ec2_s3_role.name
}

# EC2 Instance with depends_on block
resource "aws_instance" "web" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.deployer.key_name
  vpc_security_group_ids = [aws_security_group.web.id]
  subnet_id              = aws_subnet.public.id
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  # User data script to install a simple web server
  user_data = base64encode(<<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd aws-cli
              systemctl start httpd
              systemctl enable httpd
              
              # Create a simple webpage
              cat << 'HTML' > /var/www/html/index.html
              <!DOCTYPE html>
              <html>
              <head>
                  <title>Terraform EC2 Demo</title>
                  <style>
                      body { font-family: Arial, sans-serif; margin: 40px; background-color: #f0f0f0; }
                      .container { background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                      h1 { color: #333; }
                      .info { background-color: #e8f4fd; padding: 10px; border-radius: 5px; margin: 10px 0; }
                  </style>
              </head>
              <body>
                  <div class="container">
                      <h1>🚀 Hello from Terraform EC2!</h1>
                      <div class="info">
                          <p><strong>Instance ID:</strong> $(curl -s http://169.254.169.254/latest/meta-data/instance-id)</p>
                          <p><strong>Availability Zone:</strong> $(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)</p>
                          <p><strong>Instance Type:</strong> $(curl -s http://169.254.169.254/latest/meta-data/instance-type)</p>
                      </div>
                      <p>This server was created using Terraform with explicit dependencies!</p>
                  </div>
              </body>
              </html>
HTML
              
              # Test S3 access
              echo "Testing S3 access..." > /tmp/test-log.txt
              aws s3 cp /tmp/test-log.txt s3://${aws_s3_bucket.app_logs.bucket}/test-log.txt --region ${var.aws_region}
              EOF
  )

  # Explicit dependencies using depends_on
  depends_on = [
    aws_internet_gateway.main,
    aws_route_table_association.public,
    aws_s3_bucket.app_logs,
    aws_iam_instance_profile.ec2_profile
  ]

  tags = {
    Name        = "web-server-${random_string.suffix.result}"
    Environment = "dev"
    Project     = "terraform-demo"
  }
}

# Outputs
output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.web.id
}

output "instance_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.web.public_ip
}

output "instance_public_dns" {
  description = "Public DNS name of the EC2 instance"
  value       = aws_instance.web.public_dns
}

output "website_url" {
  description = "URL to access the website"
  value       = "http://${aws_instance.web.public_ip}"
}

output "ssh_connection" {
  description = "SSH connection command"
  value       = "ssh -i deployer-key-${random_string.suffix.result}.pem ec2-user@${aws_instance.web.public_ip}"
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.app_logs.bucket
}

output "private_key_file" {
  description = "Private key file location"
  value       = "deployer-key-${random_string.suffix.result}.pem"
}