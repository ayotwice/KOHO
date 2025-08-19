# PCI-DSS Controls 7.1, 7.2 - Access Control
package pci.access_control

# Control 7.1 - Limit access to system components and cardholder data
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    
    # Check for overly broad permissions
    statement := resource.change.after.policy.Statement[_]
    statement.Effect == "Allow"
    statement.Action[_] == "*"
    statement.Resource[_] == "*"
    
    msg := sprintf("IAM policy '%s' grants excessive permissions (*:*) (Control 7.1)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_policy"
    
    # Check for public read/write access
    statement := resource.change.after.policy.Statement[_]
    statement.Effect == "Allow"
    statement.Principal == "*"
    
    msg := sprintf("S3 bucket policy '%s' allows public access (Control 7.1)", [
        resource.name
    ])
}

# Control 7.2 - Access control system for users
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_user"
    
    # Users should not have direct policies attached
    resource.change.after.force_destroy == true
    
    msg := sprintf("IAM user '%s' has force_destroy enabled, indicating direct policy attachment (Control 7.2)", [
        resource.name
    ])
}

# Ensure IAM roles have proper assume role policies
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role"
    
    # Check assume role policy
    policy := resource.change.after.assume_role_policy
    statement := policy.Statement[_]
    
    # Should not allow all principals
    statement.Principal == "*"
    
    msg := sprintf("IAM role '%s' allows any principal to assume the role (Control 7.1)", [
        resource.name
    ])
}

# Ensure S3 buckets block public access
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    
    settings := resource.change.after
    not all_public_access_blocked(settings)
    
    msg := sprintf("S3 bucket '%s' does not block all public access (Control 7.1)", [
        resource.name
    ])
}

all_public_access_blocked(settings) {
    settings.block_public_acls == true
    settings.block_public_policy == true
    settings.ignore_public_acls == true
    settings.restrict_public_buckets == true
}

# Database access should be restricted
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    # Check if database allows connections from anywhere
    not resource.change.after.vpc_security_group_ids
    
    msg := sprintf("Database '%s' is not associated with VPC security groups (Control 7.1)", [
        resource.name
    ])
}