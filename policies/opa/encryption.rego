# PCI-DSS Controls 3.4, 3.6, 4.1 - Data Encryption
package pci.encryption

# Control 3.4 - Render PAN unreadable (encryption at rest)
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    resource.change.after.storage_encrypted != true
    
    msg := sprintf("Database '%s' does not have encryption at rest enabled (Control 3.4)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_encryption"
    
    not resource.change.after.server_side_encryption_configuration
    
    msg := sprintf("S3 bucket encryption not configured for '%s' (Control 3.4)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"
    
    resource.change.after.encrypted != true
    
    msg := sprintf("EBS volume '%s' is not encrypted (Control 3.4)", [
        resource.name
    ])
}

# Control 3.6 - Key management processes
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    
    resource.change.after.enable_key_rotation != true
    
    msg := sprintf("KMS key '%s' does not have key rotation enabled (Control 3.6)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    
    resource.change.after.deletion_window_in_days < 7
    
    msg := sprintf("KMS key '%s' has deletion window less than 7 days (Control 3.6)", [
        resource.name
    ])
}

# Control 4.1 - Strong cryptography for data transmission
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    
    resource.change.after.protocol != "HTTPS"
    resource.change.after.port == "443"
    
    msg := sprintf("Load balancer listener '%s' on port 443 is not using HTTPS (Control 4.1)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    resource.change.after.protocol == "HTTPS"
    
    # Check for weak SSL policies
    ssl_policy := resource.change.after.ssl_policy
    is_weak_ssl_policy(ssl_policy)
    
    msg := sprintf("Load balancer listener '%s' uses weak SSL policy '%s' (Control 4.1)", [
        resource.name,
        ssl_policy
    ])
}

# Ensure CloudTrail logs are encrypted
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    
    not resource.change.after.kms_key_id
    
    msg := sprintf("CloudTrail '%s' logs are not encrypted with KMS (Control 3.4)", [
        resource.name
    ])
}

is_weak_ssl_policy(policy) {
    policy == "ELBSecurityPolicy-2016-08"
}

is_weak_ssl_policy(policy) {
    policy == "ELBSecurityPolicy-TLS-1-0-2015-04"
}

is_weak_ssl_policy(policy) {
    policy == "ELBSecurityPolicy-TLS-1-1-2017-01"
}