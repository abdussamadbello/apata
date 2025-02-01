# Apata
An alternative security hardener

# Linux System Hardening Tool

A comprehensive security hardening tool for Linux systems that automates the implementation of security best practices and compliance requirements.

## Features

- File system permissions hardening
- SSH configuration security
- Firewall rules management
- System controls (sysctl) optimization
- Password policy enforcement
- Audit logging configuration
- Service hardening
- User account security
- Network security
- Kernel module control
- Security tools installation
- PAM configuration
- Time synchronization
- Process accounting
- Boot security

## Prerequisites

- Python 3.8 or higher
- Root access on the target system
- Debian/Ubuntu-based Linux distribution
- Required Python packages:
  ```
  ruamel.yaml>=0.17.0
  ```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/system-hardening.git
cd system-hardening
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Make the runner script executable:
```bash
chmod +x run_hardening.py
```

## Configuration

The tool uses YAML configuration for defining hardening rules. The default configuration file is located at `system_hardening_config.yaml`.

Example configuration structure:
```yaml
file_permissions:
  critical_files:
    /etc/shadow:
      mode: "0400"
      owner: "root"
      group: "shadow"

ssh_config:
  settings:
    PermitRootLogin: "no"
    PasswordAuthentication: "no"
```

### Configuration Sections

1. **File Permissions**: Define permissions for critical system files
2. **SSH Configuration**: SSH daemon security settings
3. **Firewall Rules**: UFW firewall configuration
4. **System Controls**: Kernel parameter optimization
5. **Password Policies**: Password requirements and restrictions
6. **Audit Logging**: System auditing configuration
7. **Service Management**: Service enablement and configuration
8. **Security Tools**: Required security package installation

## Usage

### Basic Usage

Run with default configuration:
```bash
sudo ./run_hardening.py
```

Specify custom configuration file:
```bash
sudo ./run_hardening.py --config /path/to/config.yaml
```

### Additional Options

- `--dry-run`: Test configuration without making changes
- `--output-dir`: Specify directory for logs and reports
- `--log-level`: Set logging verbosity (DEBUG, INFO, WARNING, ERROR)
- `--skip-backup`: Skip backup creation before modifications
- `--sections`: Run specific hardening sections only
- `--timeout`: Set maximum execution time
- `--no-rollback`: Disable automatic rollback on failure
- `--report-format`: Choose output format (json, yaml, text)

Example:
```bash
sudo ./run_hardening.py --dry-run --sections ssh_config firewall --log-level DEBUG
```

## Output and Logging

The tool generates:
1. Detailed execution logs (`system_hardening_[timestamp].log`)
2. Results report (`hardening_results_[timestamp].[format]`)
3. Configuration backups (`[filename].backup_[timestamp]`)

Log files are stored in `/var/log/system_hardening` by default.

## Safety Features

- Automatic backup creation
- Dry run capability
- Timeout protection
- Failure rollback
- Detailed logging
- Root requirement check
- Configuration validation

## Best Practices

1. Always run with `--dry-run` first
2. Review logs after execution
3. Test in a non-production environment
4. Maintain configuration backups
5. Regular security audits
6. Monitor system behavior after hardening

## Error Handling

The tool provides detailed error messages and logs. Common issues:

1. Permission denied: Run with sudo/root
2. Configuration errors: Check YAML syntax
3. Missing dependencies: Install required packages
4. Service conflicts: Check service dependencies
5. Network issues: Verify network connectivity

## Extending the Tool

### Adding New Hardening Methods

1. Create method in `SystemHardener` class:
```python
def harden_new_feature(self) -> HardeningResult:
    try:
        # Implementation
        return HardeningResult(
            HardeningStatus.SUCCESS,
            "Successfully hardened new feature"
        )
    except Exception as e:
        return HardeningResult(
            HardeningStatus.FAILED,
            f"Error: {str(e)}"
        )
```

2. Add configuration section:
```yaml
new_feature:
  setting1: value1
  setting2: value2
```

3. Update `harden_system()` method.

### Custom Validations

Add validation methods to `ConfigurationHandler`:
```python
def _validate_new_feature(self, config: Dict[str, Any]) -> None:
    # Validation logic
    pass
```

## Security Considerations

- Regular updates
- Configuration review
- Backup strategy
- Emergency rollback plan
- Compliance requirements
- User training
- Security monitoring

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Submit pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Security best practices from CIS Benchmarks
- Industry standard hardening guidelines
- Community contributions and feedback

## Support

For issues and questions:
- Submit GitHub issues
- Check documentation
- Review common problems
- Contact maintainers
