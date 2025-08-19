# PCI-DSS Controls 10.1, 10.2 - Logging and Monitoring
package pci.logging_monitoring

# Control 10.1 - Implement audit trails
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    
    not resource.change.after.enable_logging
    
    msg := sprintf("CloudTrail '%s' does not have logging enabled (Control 10.1)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    
    not resource.change.after.include_global_service_events
    
    msg := sprintf("CloudTrail '%s' does not include global service events (Control 10.1)", [
        resource.name
    ])
}

# Control 10.2 - Automated audit trails for all system components
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    # Database should have logging enabled
    logs := resource.change.after.enabled_cloudwatch_logs_exports
    not logs
    
    msg := sprintf("Database '%s' does not have CloudWatch logs enabled (Control 10.2)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    # Check for required log types
    logs := resource.change.after.enabled_cloudwatch_logs_exports
    
    not has_error_logs(logs)
    
    msg := sprintf("Database '%s' is missing error logs (Control 10.2)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    # Check for required log types
    logs := resource.change.after.enabled_cloudwatch_logs_exports
    
    not has_general_logs(logs)
    
    msg := sprintf("Database '%s' is missing general logs (Control 10.2)", [
        resource.name
    ])
}

# CloudTrail should have data events for sensitive resources
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    
    # Should have event selectors for S3 data events
    not resource.change.after.event_selector
    
    msg := sprintf("CloudTrail '%s' does not have data event selectors configured (Control 10.2)", [
        resource.name
    ])
}

# S3 buckets should have access logging
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    
    # Check if this is a data bucket (contains sensitive data)
    contains(resource.name, "data")
    
    # Should have corresponding logging configuration
    not has_s3_logging_config(resource.name)
    
    msg := sprintf("S3 bucket '%s' does not have access logging configured (Control 10.2)", [
        resource.name
    ])
}

# Database backup retention should be adequate
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    resource.change.after.backup_retention_period < 7
    
    msg := sprintf("Database '%s' backup retention period is less than 7 days (Control 10.1)", [
        resource.name
    ])
}

# Helper function to check if S3 logging is configured
has_s3_logging_config(bucket_name) {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_logging"
    contains(resource.name, bucket_name)
}

# VPC Flow Logs should be enabled for network monitoring
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_vpc"
    
    # Should have corresponding VPC flow logs
    not has_vpc_flow_logs(resource.name)
    
    msg := sprintf("VPC '%s' does not have flow logs enabled (Control 10.2)", [
        resource.name
    ])
}

has_vpc_flow_logs(vpc_name) {
    resource := input.resource_changes[_]
    resource.type == "aws_flow_log"
    contains(resource.name, vpc_name)
}

has_error_logs(logs) {
    logs[_] == "error"
}

has_general_logs(logs) {
    logs[_] == "general"
}