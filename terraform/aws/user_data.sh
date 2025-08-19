#!/bin/bash
# PCI-DSS Compliant System Configuration (Control 2.2)

# Update system
yum update -y

# Install CloudWatch agent for logging (Control 10.2)
yum install -y amazon-cloudwatch-agent

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/secure",
            "log_group_name": "/aws/ec2/pci/secure",
            "log_stream_name": "{instance_id}"
          },
          {
            "file_path": "/var/log/messages",
            "log_group_name": "/aws/ec2/pci/messages",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Disable unnecessary services (Control 2.2)
systemctl disable rpcbind
systemctl disable nfs-server
systemctl disable telnet

# Configure SSH hardening (Control 2.2)
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Set up log rotation
cat > /etc/logrotate.d/pci-logs << 'EOF'
/var/log/pci/*.log {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF

# Create PCI log directory
mkdir -p /var/log/pci
chmod 755 /var/log/pci