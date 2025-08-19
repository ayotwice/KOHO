output "vpc_id" {
  description = "ID of the PCI-compliant VPC"
  value       = aws_vpc.pci_vpc.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "kms_key_id" {
  description = "ID of the PCI encryption key"
  value       = aws_kms_key.pci_key.id
}

output "database_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.pci_database.endpoint
  sensitive   = true
}

output "s3_bucket_name" {
  description = "Name of the PCI data bucket"
  value       = aws_s3_bucket.pci_data.bucket
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail"
  value       = aws_cloudtrail.pci_trail.name
}

output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = aws_lb.pci_alb.dns_name
}