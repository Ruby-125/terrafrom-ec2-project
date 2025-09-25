# Terraform EC2 Project

Creates an EC2 instance on AWS with a simple web server.

## What it creates:
- EC2 instance with web server
- VPC and networking components
- Security group for web access
- S3 bucket for logs

## How to use:

1. **Setup AWS credentials**
   ```
   aws configure
   ```

2. **Clone and run**
   ```
   git clone <your-repo-url>
   cd terraform-ec2-project
   terraform init
   terraform plan
   terraform apply
   ```

3. **Access your web server**
   - Use the IP address from the output
   - Visit: `http://YOUR_EC2_IP`

4. **Clean up when done**
   ```
   terraform destroy
   ```

## Requirements:
- AWS account
- Terraform installed
- AWS CLI configured

That's it! 
