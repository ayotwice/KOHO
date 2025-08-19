# PCI-DSS Compliance as Code

[![Compliance Validation](https://github.com/ayotwice/KOHO/actions/workflows/compliance.yml/badge.svg)](https://github.com/ayotwice/KOHO/actions/workflows/compliance.yml)

Automated PCI-DSS compliance validation using Terraform and OPA (Conftest). This repository provides ready-to-run infrastructure as code with built-in compliance validation for high-priority PCI-DSS controls.

## 🎯 Implemented Controls

| Control | Description | Status |
|---------|-------------|--------|
| **1.1, 1.2, 1.3** | Network Security (Firewalls, Segmentation) | ✅ |
| **2.2** | System Configuration Standards | ✅ |
| **3.4, 3.6** | Data Encryption (At-rest, Key Management) | ✅ |
| **4.1** | Encryption in Transit (HTTPS/TLS) | ✅ |
| **7.1, 7.2** | Access Control (IAM, RBAC) | ✅ |
| **10.1, 10.2** | Logging and Monitoring | ✅ |

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/ayotwice/KOHO.git
cd KOHO

# Install dependencies
make install

# Run compliance validation
make validate

# Deploy infrastructure
make deploy
```

## 📁 Repository Structure

```
PCI-DSS-PaC/
├── terraform/aws/          # Terraform infrastructure code
│   ├── main.tf            # Main infrastructure resources
│   ├── variables.tf       # Input variables
│   ├── outputs.tf         # Output values
│   └── user_data.sh       # EC2 hardening script
├── policies/opa/           # OPA compliance policies
│   ├── main.rego          # Main PCI-DSS policies
│   ├── network_security.rego    # Controls 1.1, 1.2, 1.3
│   ├── encryption.rego          # Controls 3.4, 3.6, 4.1
│   ├── access_control.rego      # Controls 7.1, 7.2
│   ├── logging_monitoring.rego  # Controls 10.1, 10.2
│   └── system_configuration.rego # Control 2.2
├── tests/fixtures/         # Test scenarios
│   ├── compliant_plan.json      # Compliant configuration
│   └── non_compliant_plan.json  # Non-compliant examples
├── .github/workflows/      # GitHub Actions CI/CD
│   └── compliance.yml           # Automated validation
├── Makefile               # Automation commands
├── SETUP.md              # Detailed setup guide
└── README.md             # This file
```

## 🔧 Available Commands

```bash
make help          # Show all available commands
make install       # Install Terraform and Conftest
make fmt           # Format Terraform code
make validate      # Run full compliance validation
make test          # Test policies with fixtures
make plan          # Generate Terraform plan
make deploy        # Deploy infrastructure
make destroy       # Destroy infrastructure
make clean         # Clean temporary files
make report        # Generate compliance report
```

## 🏗️ Infrastructure Components

### Network Security (Controls 1.1, 1.2, 1.3)
- VPC with private/public subnets
- Security groups with least privilege
- Network segmentation (DMZ, CDE)
- No direct internet access to databases

### Data Encryption (Controls 3.4, 3.6)
- KMS encryption keys with rotation
- Encrypted RDS instances
- Encrypted S3 buckets
- Encrypted EBS volumes

### Access Control (Controls 7.1, 7.2)
- IAM roles with least privilege
- S3 bucket policies blocking public access
- Database access restrictions

### Logging & Monitoring (Controls 10.1, 10.2)
- CloudTrail for API logging
- CloudWatch for system monitoring
- Database audit logs
- Encrypted log storage

### System Configuration (Control 2.2)
- Hardened EC2 instances
- Disabled unnecessary services
- SSH key-based authentication
- Current software versions

## 🔍 Compliance Validation

The repository includes comprehensive OPA policies that validate:

- ✅ Network security configurations
- ✅ Encryption at rest and in transit
- ✅ Access control policies
- ✅ Logging and monitoring setup
- ✅ System hardening standards

## 🚦 GitHub Actions Workflow

Automated pipeline includes:

1. **Terraform Validation** - Format, init, validate, plan
2. **Policy Validation** - OPA/Conftest compliance checks
3. **Security Scanning** - Trivy vulnerability scanning
4. **Compliance Reporting** - Automated compliance reports
5. **Deployment** - Infrastructure deployment (main branch)

## 📋 Prerequisites

- AWS Account with appropriate permissions
- Terraform >= 1.6.0
- Conftest (OPA) for policy validation
- Make for automation

## 🔐 Required AWS Permissions

The deployment requires permissions for:
- EC2 (VPC, Security Groups, Instances)
- RDS (Database instances)
- S3 (Buckets, encryption)
- KMS (Key management)
- IAM (Roles, policies)
- CloudTrail (Audit logging)
- ELB (Load balancers)
- ACM (SSL certificates)

## 📖 Documentation

- [Setup Guide](SETUP.md) - Detailed setup instructions
- [GitHub Actions Setup](SETUP.md#github-actions-setup) - CI/CD configuration
- [Customization Guide](SETUP.md#customization) - Adding new controls

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add/modify controls and policies
4. Test with fixtures
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This repository provides a foundation for PCI-DSS compliance but should be reviewed and customized for your specific environment and requirements. Always consult with compliance experts for production deployments.