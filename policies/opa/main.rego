package main

# PCI-DSS Compliance Policies

# Control 1.1 - SSH should not be open to the world
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    
    rule := resource.change.after.ingress[_]
    rule.from_port == 22
    rule.cidr_blocks[_] == "0.0.0.0/0"
    
    msg := sprintf("Security group '%s' allows SSH from anywhere (Control 1.1)", [resource.name])
}

# Control 3.4 - Databases must be encrypted
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.storage_encrypted == false
    
    msg := sprintf("Database '%s' is not encrypted (Control 3.4)", [resource.name])
}

# Control 3.6 - KMS keys must have rotation enabled  
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    resource.change.after.enable_key_rotation == false
    
    msg := sprintf("KMS key '%s' does not have rotation enabled (Control 3.6)", [resource.name])
}

# Control 7.1 - IAM policies should not grant full access
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    
    statement := resource.change.after.policy.Statement[_]
    statement.Effect == "Allow"
    statement.Action == "*"
    statement.Resource == "*"
    
    msg := sprintf("IAM policy '%s' grants excessive permissions (Control 7.1)", [resource.name])
}

# Control 1.3 - Databases should not be publicly accessible
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.publicly_accessible == true
    
    msg := sprintf("Database '%s' is publicly accessible (Control 1.3)", [resource.name])
}

# Control 7.1 - S3 buckets should block public access
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    
    resource.change.after.block_public_acls == false
    
    msg := sprintf("S3 bucket '%s' does not block public ACLs (Control 7.1)", [resource.name])
}