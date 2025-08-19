# PCI-DSS Controls 1.1, 1.2, 1.3 - Network Security
package pci.network_security

# Control 1.1 - Firewall configuration standards
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    
    # Check for overly permissive ingress rules
    rule := resource.change.after.ingress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port != 443
    rule.from_port != 80
    
    msg := sprintf("Security group '%s' allows unrestricted access on port %d (Control 1.1)", [
        resource.name, 
        rule.from_port
    ])
}

# Control 1.2 - Network segmentation
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    
    # Database security groups should not allow direct internet access
    contains(resource.name, "db")
    rule := resource.change.after.ingress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    
    msg := sprintf("Database security group '%s' allows direct internet access (Control 1.2)", [
        resource.name
    ])
}

# Control 1.3 - Prohibit direct public access to cardholder data
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    
    resource.change.after.publicly_accessible == true
    
    msg := sprintf("Database '%s' is publicly accessible (Control 1.3)", [
        resource.name
    ])
}

# Ensure VPC has proper CIDR blocks
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_vpc"
    
    # VPC CIDR should be private
    cidr := resource.change.after.cidr_block
    not is_private_cidr(cidr)
    
    msg := sprintf("VPC '%s' uses public CIDR block '%s' (Control 1.2)", [
        resource.name,
        cidr
    ])
}

is_private_cidr(cidr) {
    startswith(cidr, "10.")
}

is_private_cidr(cidr) {
    startswith(cidr, "172.")
}

is_private_cidr(cidr) {
    startswith(cidr, "192.168.")
}