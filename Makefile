.PHONY: help install validate test deploy clean fmt plan apply destroy report

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies (Terraform, Conftest)
	@echo "Installing dependencies..."
	@which terraform > /dev/null || (echo "Please install Terraform" && exit 1)
	@which conftest > /dev/null || (echo "Installing Conftest..." && \
		wget -q https://github.com/open-policy-agent/conftest/releases/download/v0.46.0/conftest_0.46.0_Linux_x86_64.tar.gz && \
		tar xzf conftest_0.46.0_Linux_x86_64.tar.gz && \
		sudo mv conftest /usr/local/bin && \
		rm conftest_0.46.0_Linux_x86_64.tar.gz)
	@echo "Dependencies installed successfully"

fmt: ## Format Terraform code
	@echo "Formatting Terraform code..."
	terraform fmt -recursive terraform/

validate: install ## Run compliance validation
	@echo "Running PCI-DSS compliance validation..."
	@cd terraform/aws && terraform init
	@cd terraform/aws && terraform validate
	@cd terraform/aws && terraform plan -out=tfplan.binary
	@cd terraform/aws && terraform show -json tfplan.binary > tfplan.json
	@echo "Testing PCI-DSS compliance..."
	conftest test --policy policies/opa/main.rego terraform/aws/tfplan.json --output=table
	@echo "All compliance tests passed!"

test: install ## Run policy tests with fixtures
	@echo "Running policy tests with fixtures..."
	@echo "Testing compliant configuration..."
	conftest test --policy policies/opa/main.rego tests/fixtures/compliant_plan.json --output=table
	@echo "Testing non-compliant configuration (should fail)..."
	! conftest test --policy policies/opa/main.rego tests/fixtures/non_compliant_plan.json --output=table
	@echo "Policy tests completed successfully!"

plan: ## Generate Terraform plan
	@echo "Generating Terraform plan..."
	@cd terraform/aws && terraform init
	@cd terraform/aws && terraform plan

apply: validate ## Deploy infrastructure
	@echo "Deploying PCI-DSS compliant infrastructure..."
	@cd terraform/aws && terraform apply -auto-approve
	@echo "Infrastructure deployed successfully!"

destroy: ## Destroy infrastructure
	@echo "Destroying infrastructure..."
	@cd terraform/aws && terraform destroy -auto-approve
	@echo "Infrastructure destroyed!"

deploy: apply ## Alias for apply

clean: ## Clean up temporary files
	@echo "Cleaning up temporary files..."
	rm -f terraform/aws/tfplan.binary
	rm -f terraform/aws/tfplan.json
	rm -f terraform/aws/.terraform.lock.hcl
	rm -rf terraform/aws/.terraform/
	@echo "Cleanup completed!"

report: ## Generate compliance report
	@echo "Generating PCI-DSS compliance report..."
	@echo "# PCI-DSS Compliance Report" > compliance-report.md
	@echo "" >> compliance-report.md
	@echo "Generated on: $$(date)" >> compliance-report.md
	@echo "" >> compliance-report.md
	@echo "## Implemented Controls" >> compliance-report.md
	@echo "- **1.1, 1.2, 1.3** - Network Security" >> compliance-report.md
	@echo "- **2.2** - System Configuration" >> compliance-report.md
	@echo "- **3.4, 3.6** - Data Encryption" >> compliance-report.md
	@echo "- **4.1** - Encryption in Transit" >> compliance-report.md
	@echo "- **7.1, 7.2** - Access Control" >> compliance-report.md
	@echo "- **10.1, 10.2** - Logging and Monitoring" >> compliance-report.md
	@echo "Report generated: compliance-report.md"