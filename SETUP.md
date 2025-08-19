# PCI-DSS Compliance as Code - Setup Guide

## Prerequisites

- **Terraform** >= 1.6.0
- **AWS CLI** configured with appropriate permissions
- **Conftest** (OPA) for policy validation
- **Make** for automation

## Quick Setup

1. **Clone and Configure**
   ```bash
   git clone <repository-url>
   cd PCI-DSS-PaC
   cp terraform/aws/terraform.tfvars.example terraform/aws/terraform.tfvars
   ```

2. **Set Environment Variables**
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export TF_VAR_db_password="secure-database-password"
   ```

3. **Install Dependencies**
   ```bash
   make install
   ```

4. **Validate Compliance**
   ```bash
   make validate
   ```

5. **Deploy Infrastructure**
   ```bash
   make deploy
   ```

## GitHub Actions Setup

### Required Secrets

Configure these secrets in your GitHub repository:

- `AWS_ACCESS_KEY_ID` - AWS access key
- `AWS_SECRET_ACCESS_KEY` - AWS secret key  
- `DB_PASSWORD` - Database password

### Workflow Triggers

- **Push to main/develop** - Full validation and deployment
- **Pull Request** - Validation and compliance report
- **Manual trigger** - On-demand validation

## AWS Permissions

The AWS user/role needs these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "rds:*",
        "s3:*",
        "kms:*",
        "iam:*",
        "cloudtrail:*",
        "elasticloadbalancing:*",
        "acm:*",
        "logs:*"
      ],
      "Resource": "*"
    }
  ]
}
```

## Implemented Controls

| Control | Description | Implementation |
|---------|-------------|----------------|
| 1.1, 1.2, 1.3 | Network Security | VPC, Security Groups, Network Segmentation |
| 2.2 | System Configuration | Hardened EC2 instances, Launch templates |
| 3.4, 3.6 | Data Encryption | KMS encryption, RDS encryption, S3 encryption |
| 4.1 | Encryption in Transit | HTTPS/TLS, SSL certificates |
| 7.1, 7.2 | Access Control | IAM roles, least privilege, S3 bucket policies |
| 10.1, 10.2 | Logging & Monitoring | CloudTrail, CloudWatch, audit logs |

## Usage Commands

```bash
make help          # Show available commands
make validate      # Run compliance validation
make test          # Test policies with fixtures
make deploy        # Deploy infrastructure
make destroy       # Destroy infrastructure
make clean         # Clean temporary files
make report        # Generate compliance report
```

## Customization

### Adding New Controls

1. Create Terraform resources in `terraform/aws/`
2. Add OPA policies in `policies/opa/`
3. Update test fixtures in `tests/fixtures/`
4. Update documentation

### Modifying Policies

Edit `.rego` files in `policies/opa/` to adjust compliance rules.

### Environment-Specific Configuration

Update `terraform.tfvars` for different environments (dev, staging, prod).

## Troubleshooting

### Common Issues

1. **Terraform Init Fails**
   - Check AWS credentials
   - Verify region configuration

2. **Policy Validation Fails**
   - Review OPA policy syntax
   - Check Terraform plan JSON format

3. **Deployment Fails**
   - Verify AWS permissions
   - Check resource limits/quotas

### Support

- Review GitHub Actions logs for detailed error messages
- Check Terraform plan output for resource conflicts
- Validate OPA policies with test fixtures