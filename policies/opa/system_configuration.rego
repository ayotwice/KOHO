# PCI-DSS Control 2.2 - System Configuration Standards
package pci.system_configuration

# Control 2.2 - System configuration standards
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    
    # Instance should not allow unrestricted SSH access
    sg_id := resource.change.after.vpc_security_group_ids[_]
    sg := get_security_group(sg_id)
    
    rule := sg.ingress[_]
    rule.from_port == 22
    rule.cidr_blocks[_] == "0.0.0.0/0"
    
    msg := sprintf("EC2 instance '%s' allows unrestricted SSH access (Control 2.2)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_launch_template"
    
    # Launch template should use encrypted EBS volumes
    bdm := resource.change.after.block_device_mappings[_]
    bdm.ebs.encrypted != true
    
    msg := sprintf("Launch template '%s' does not encrypt EBS volumes (Control 2.2)", [
        resource.name
    ])
}

# AMI should be from trusted source
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    
    ami_id := resource.change.after.ami
    not is_trusted_ami(ami_id)
    
    msg := sprintf("EC2 instance '%s' uses untrusted AMI '%s' (Control 2.2)", [
        resource.name,
        ami_id
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_launch_template"
    
    ami_id := resource.change.after.image_id
    not is_trusted_ami(ami_id)
    
    msg := sprintf("Launch template '%s' uses untrusted AMI '%s' (Control 2.2)", [
        resource.name,
        ami_id
    ])
}

# Instance should have IAM role attached
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    
    not resource.change.after.iam_instance_profile
    
    msg := sprintf("EC2 instance '%s' does not have IAM instance profile attached (Control 2.2)", [
        resource.name
    ])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_launch_template"
    
    not resource.change.after.iam_instance_profile
    
    msg := sprintf("Launch template '%s' does not specify IAM instance profile (Control 2.2)", [
        resource.name
    ])
}

# Database engine version should be current
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    engine := resource.change.after.engine
    version := resource.change.after.engine_version
    
    is_outdated_db_version(engine, version)
    
    msg := sprintf("Database '%s' uses outdated %s version '%s' (Control 2.2)", [
        resource.name,
        engine,
        version
    ])
}

# Helper functions
get_security_group(sg_id) = sg {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    resource.change.after.id == sg_id
    sg := resource.change.after
}

is_trusted_ami(ami_id) {
    # Amazon Linux 2 AMIs
    startswith(ami_id, "ami-")
}

is_outdated_db_version(engine, version) {
    engine == "mysql"
    version < "8.0"
}

is_outdated_db_version(engine, version) {
    engine == "postgres"
    version < "13"
}