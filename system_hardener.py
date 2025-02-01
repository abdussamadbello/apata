
import os
import subprocess
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from pathlib import Path
import shutil
from dataclasses import dataclass
from enum import Enum, auto

class HardeningStatus(Enum):
    SUCCESS = auto()
    FAILED = auto()
    SKIPPED = auto()

@dataclass
class HardeningResult:
    status: HardeningStatus
    message: str
    details: Optional[Dict[str, Any]] = None

class SystemHardener:
    """Implements system hardening operations using configuration"""
    
    def __init__(self, config_handler, logger: Optional[logging.Logger] = None, 
                 dry_run: bool = False):
        """Initialize the system hardener
        
        Args:
            config_handler: Configuration handler instance
            logger: Optional logger instance
            dry_run: Whether to perform dry run
        """
        self.config_handler = config_handler
        self.logger = logger or self._setup_logger()
        self.dry_run = dry_run
        self.results: List[HardeningResult] = []

    def _setup_logger(self) -> logging.Logger:
        """Set up logging"""
        logger = logging.getLogger("SystemHardener")
        logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # Add file handler
        fh = logging.FileHandler('system_hardening.log')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
        return logger

    def execute_command(self, command: str, description: str) -> Tuple[bool, str]:
        """Execute a system command safely"""
        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would execute: {command}")
            return True, "Dry run - command would be executed"

        try:
            self.logger.info(f"Executing: {description}")
            process = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            self.logger.info(f"Successfully executed: {description}")
            return True, process.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {e.stderr}")
            return False, e.stderr
        except Exception as e:
            self.logger.error(f"Error executing command: {e}")
            return False, str(e)

    def backup_file(self, file_path: str) -> Optional[str]:
        """Create backup of a file before modification"""
        try:
            path = Path(file_path)
            if not path.exists():
                return None
                
            backup_path = path.with_suffix(
                f"{path.suffix}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            shutil.copy2(path, backup_path)
            self.logger.info(f"Created backup at {backup_path}")
            return str(backup_path)
        except Exception as e:
            self.logger.error(f"Failed to create backup of {file_path}: {e}")
            return None

    def harden_file_permissions(self) -> HardeningResult:
        """Secure critical file permissions"""
        self.logger.info("Hardening file permissions...")
        
        try:
            config = self.config_handler.get_section('file_permissions')
            critical_files = config.get('critical_files', {})
            
            results = []
            for file_path, settings in critical_files.items():
                if not Path(file_path).exists():
                    self.logger.warning(f"File not found: {file_path}")
                    continue
                
                # Backup file
                self.backup_file(file_path)
                
                # Set ownership
                success, output = self.execute_command(
                    f"chown {settings['owner']}:{settings['group']} {file_path}",
                    f"Setting ownership for {file_path}"
                )
                results.append(success)
                
                # Set permissions
                success, output = self.execute_command(
                    f"chmod {settings['mode']} {file_path}",
                    f"Setting permissions for {file_path}"
                )
                results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully hardened file permissions",
                    {"files": list(critical_files.keys())}
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to harden some file permissions",
                    {"files": list(critical_files.keys())}
                )
                
        except Exception as e:
            self.logger.error(f"Error hardening file permissions: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error hardening file permissions: {str(e)}"
            )

    def harden_ssh(self) -> HardeningResult:
        """Harden SSH configuration"""
        self.logger.info("Hardening SSH configuration...")
        
        try:
            config = self.config_handler.get_section('ssh_config')
            ssh_settings = config.get('settings', {})
            ssh_config_path = "/etc/ssh/sshd_config"
            
            if not Path(ssh_config_path).exists():
                return HardeningResult(
                    HardeningStatus.SKIPPED,
                    "SSH configuration file not found"
                )
            
            # Backup configuration
            backup_path = self.backup_file(ssh_config_path)
            if not backup_path and not self.dry_run:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to create SSH config backup"
                )
            
            try:
                # Read current config
                with open(ssh_config_path, 'r') as f:
                    current_config = f.readlines()
                
                # Update or add settings
                new_config = []
                processed_settings = set()
                
                for line in current_config:
                    line_stripped = line.strip()
                    if line_stripped and not line_stripped.startswith('#'):
                        key = line_stripped.split()[0]
                        if key in ssh_settings:
                            new_config.append(f"{key} {ssh_settings[key]}\n")
                            processed_settings.add(key)
                            continue
                    new_config.append(line)
                
                # Add missing settings
                for key, value in ssh_settings.items():
                    if key not in processed_settings:
                        new_config.append(f"{key} {value}\n")
                
                if not self.dry_run:
                    # Write updated config
                    with open(ssh_config_path, 'w') as f:
                        f.writelines(new_config)
                    
                    # Restart SSH service
                    success, output = self.execute_command(
                        "systemctl restart sshd",
                        "Restarting SSH service"
                    )
                    if not success:
                        raise Exception(f"Failed to restart SSH service: {output}")
                
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully hardened SSH configuration",
                    {"settings": ssh_settings}
                )
                
            except Exception as e:
                # Restore backup on failure
                if backup_path and not self.dry_run:
                    shutil.copy2(backup_path, ssh_config_path)
                raise
                
        except Exception as e:
            self.logger.error(f"Error hardening SSH configuration: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error hardening SSH configuration: {str(e)}"
            )

    def harden_firewall(self) -> HardeningResult:
        """Configure and harden firewall settings"""
        self.logger.info("Hardening firewall configuration...")
        
        try:
            config = self.config_handler.get_section('firewall')
            
            # Install UFW if not present
            success, output = self.execute_command(
                "apt-get install -y ufw",
                "Installing UFW firewall"
            )
            if not success:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    f"Failed to install UFW: {output}"
                )
            
            # Apply firewall rules
            results = []
            
            # Default policies
            for policy in config.get('default_policies', []):
                success, output = self.execute_command(
                    policy,
                    f"Setting firewall policy: {policy}"
                )
                results.append(success)
            
            # Allowed services
            for rule in config.get('allowed_services', []):
                success, output = self.execute_command(
                    rule,
                    f"Adding firewall allow rule: {rule}"
                )
                results.append(success)
            
            # Denied services
            for rule in config.get('denied_services', []):
                success, output = self.execute_command(
                    rule,
                    f"Adding firewall deny rule: {rule}"
                )
                results.append(success)
            
            # Additional settings
            for setting in config.get('settings', []):
                success, output = self.execute_command(
                    setting,
                    f"Applying firewall setting: {setting}"
                )
                results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully hardened firewall configuration",
                    {
                        "allowed": config.get('allowed_services', []),
                        "denied": config.get('denied_services', [])
                    }
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to apply some firewall rules"
                )
                
        except Exception as e:
            self.logger.error(f"Error hardening firewall: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error hardening firewall: {str(e)}"
            )

    def harden_sysctl(self) -> HardeningResult:
        """Configure and optimize sysctl settings"""
        self.logger.info("Configuring sysctl settings...")
        
        try:
            config = self.config_handler.get_section('sysctl')
            all_settings = {}
            
            # Combine all sysctl settings from different categories
            for category in ['network', 'kernel', 'filesystem']:
                all_settings.update(config.get(category, {}))
            
            # Backup current sysctl configuration
            sysctl_conf = "/etc/sysctl.conf"
            self.backup_file(sysctl_conf)
            
            # Apply settings
            results = []
            for key, value in all_settings.items():
                success, output = self.execute_command(
                    f"sysctl -w {key}={value}",
                    f"Setting sysctl parameter: {key}"
                )
                results.append(success)
                
                if not self.dry_run:
                    # Add to sysctl.conf for persistence
                    with open(sysctl_conf, 'a') as f:
                        f.write(f"\n{key} = {value}\n")
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully configured sysctl settings",
                    {"applied_settings": all_settings}
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to apply some sysctl settings"
                )
                
        except Exception as e:
            self.logger.error(f"Error configuring sysctl: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error configuring sysctl: {str(e)}"
            )

    def harden_password_policy(self) -> HardeningResult:
        """Configure password and login policies"""
        self.logger.info("Configuring password policies...")
        
        try:
            config = self.config_handler.get_section('password_policy')
            
            # Configure PAM password quality
            pwquality_conf = "/etc/security/pwquality.conf"
            self.backup_file(pwquality_conf)
            
            if not self.dry_run:
                with open(pwquality_conf, 'w') as f:
                    for key, value in config['pwquality'].items():
                        f.write(f"{key} = {value}\n")
            
            # Configure login.defs
            login_defs = "/etc/login.defs"
            self.backup_file(login_defs)
            
            success = True
            if not self.dry_run:
                with open(login_defs, 'r') as f:
                    lines = f.readlines()
                
                # Update existing settings
                login_settings = config.get('login_defs', {})
                modified_lines = []
                processed_settings = set()
                
                for line in lines:
                    line_stripped = line.strip()
                    if line_stripped and not line_stripped.startswith('#'):
                        key = line_stripped.split()[0]
                        if key in login_settings:
                            modified_lines.append(f"{key}\t{login_settings[key]}\n")
                            processed_settings.add(key)
                            continue
                    modified_lines.append(line)
                
                # Add new settings
                for key, value in login_settings.items():
                    if key not in processed_settings:
                        modified_lines.append(f"{key}\t{value}\n")
                
                with open(login_defs, 'w') as f:
                    f.writelines(modified_lines)
            
            return HardeningResult(
                HardeningStatus.SUCCESS if success else HardeningStatus.FAILED,
                "Successfully configured password policies" if success else "Failed to configure some password policies",
                {
                    "pwquality": config.get('pwquality', {}),
                    "login_defs": config.get('login_defs', {})
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error configuring password policies: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error configuring password policies: {str(e)}"
            )

    def harden_audit_logging(self) -> HardeningResult:
        """Configure audit logging system"""
        self.logger.info("Configuring audit logging...")
        
        try:
            config = self.config_handler.get_section('audit_logging')
            
            # Install audit package if not present
            success, output = self.execute_command(
                "apt-get install -y auditd audispd-plugins",
                "Installing audit packages"
            )
            
            if not success:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    f"Failed to install audit packages: {output}"
                )
            
            # Configure audit rules
            rules_file = "/etc/audit/rules.d/hardening.rules"
            self.backup_file(rules_file)
            
            all_rules = []
            for category in ['file_system', 'system_calls', 'user_monitoring']:
                all_rules.extend(config.get('rules', {}).get(category, []))
            
            if not self.dry_run:
                with open(rules_file, 'w') as f:
                    f.write("\n".join(all_rules) + "\n")
            
            # Configure audit daemon
            auditd_conf = "/etc/audit/auditd.conf"
            self.backup_file(auditd_conf)
            
            if not self.dry_run:
                with open(auditd_conf, 'w') as f:
                    for key, value in config.get('settings', {}).items():
                        f.write(f"{key} = {value}\n")
            
            # Restart audit service
            success, output = self.execute_command(
                "service auditd restart",
                "Restarting audit daemon"
            )
            
            if success:
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully configured audit logging",
                    {
                        "rules_count": len(all_rules),
                        "settings": config.get('settings', {})
                    }
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    f"Failed to restart audit service: {output}"
                )
                
        except Exception as e:
            self.logger.error(f"Error configuring audit logging: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error configuring audit logging: {str(e)}"
            )

    def harden_services(self) -> HardeningResult:
        """Configure and secure system services"""
        self.logger.info("Configuring system services...")
        
        try:
            config = self.config_handler.get_section('services')
            results = []
            
            # Disable unnecessary services
            for service in config.get('disable', []):
                success, output = self.execute_command(
                    f"systemctl disable {service}",
                    f"Disabling service: {service}"
                )
                results.append(success)
                
                if success:
                    success, output = self.execute_command(
                        f"systemctl stop {service}",
                        f"Stopping service: {service}"
                    )
                    results.append(success)
            
            # Configure NTP if specified
            if 'ntp' in config:
                ntp_conf = "/etc/ntp.conf"
                self.backup_file(ntp_conf)
                
                if not self.dry_run:
                    with open(ntp_conf, 'w') as f:
                        # Write NTP servers
                        for server in config['ntp'].get('servers', []):
                            f.write(f"server {server} iburst\n")
                        
                        # Write NTP settings
                        for setting in config['ntp'].get('settings', []):
                            f.write(f"{setting}\n")
                
                # Restart NTP service
                success, output = self.execute_command(
                    "systemctl restart ntp",
                    "Restarting NTP service"
                )
                results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully configured system services",
                    {
                        "disabled_services": config.get('disable', []),
                        "ntp_configured": 'ntp' in config
                    }
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to configure some system services"
                )
                
        except Exception as e:
            self.logger.error(f"Error configuring system services: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error configuring system services: {str(e)}"
            )
    
    def harden_user_accounts(self) -> HardeningResult:
        """Secure user accounts and authentication"""
        self.logger.info("Hardening user accounts...")
        
        try:
            # Lock root account
            success, output = self.execute_command(
                "passwd -l root",
                "Locking root account"
            )
            
            results = [success]
            account_actions = []

            # Find users with UID >= 1000 (normal users)
            success, output = self.execute_command(
                "awk -F: '$3 >= 1000 {print $1}' /etc/passwd",
                "Getting user list"
            )
            
            if success:
                users = output.strip().split('\n')
                for user in users:
                    # Check last login
                    success, last_login = self.execute_command(
                        f"lastlog -u {user}",
                        f"Checking last login for {user}"
                    )
                    
                    if "Never logged in" in last_login:
                        success, output = self.execute_command(
                            f"usermod -L {user}",
                            f"Locking inactive user account: {user}"
                        )
                        results.append(success)
                        if success:
                            account_actions.append(f"Locked inactive account: {user}")

                    # Set password expiry
                    success, output = self.execute_command(
                        f"chage --maxdays 90 --mindays 7 --warndays 7 {user}",
                        f"Setting password expiry for {user}"
                    )
                    results.append(success)
                    if success:
                        account_actions.append(f"Set password policy for: {user}")

            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully hardened user accounts",
                    {"actions": account_actions}
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to complete some user account hardening steps"
                )

        except Exception as e:
            self.logger.error(f"Error hardening user accounts: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error hardening user accounts: {str(e)}"
            )

    def harden_file_systems(self) -> HardeningResult:
        """Secure file system configurations"""
        self.logger.info("Hardening file systems...")
        
        try:
            # Define secure mount options for different file systems
            mount_options = {
                "/tmp": "defaults,noexec,nosuid,nodev",
                "/var": "defaults,nosuid",
                "/var/log": "defaults,nosuid,nodev",
                "/var/log/audit": "defaults,nosuid,nodev",
                "/home": "defaults,nosuid,nodev",
                "/dev/shm": "defaults,noexec,nosuid,nodev"
            }
            
            fstab_path = "/etc/fstab"
            self.backup_file(fstab_path)
            
            # Read current fstab
            with open(fstab_path, 'r') as f:
                fstab_lines = f.readlines()
            
            # Update mount options
            modified_lines = []
            mount_points_found = set()
            
            for line in fstab_lines:
                if not line.strip() or line.startswith('#'):
                    modified_lines.append(line)
                    continue
                
                fields = line.split()
                if len(fields) >= 4:
                    mount_point = fields[1]
                    if mount_point in mount_options:
                        fields[3] = mount_options[mount_point]
                        modified_lines.append('\t'.join(fields) + '\n')
                        mount_points_found.add(mount_point)
                    else:
                        modified_lines.append(line)
            
            # Add missing mount points if they exist on the system
            for mount_point, options in mount_options.items():
                if mount_point not in mount_points_found and os.path.exists(mount_point):
                    if mount_point == "/dev/shm":
                        modified_lines.append(f"tmpfs\t{mount_point}\ttmpfs\t{options}\t0 0\n")
            
            if not self.dry_run:
                with open(fstab_path, 'w') as f:
                    f.writelines(modified_lines)
                
                # Remount all file systems
                success, output = self.execute_command(
                    "mount -a",
                    "Remounting file systems"
                )
                if not success:
                    return HardeningResult(
                        HardeningStatus.FAILED,
                        f"Failed to remount file systems: {output}"
                    )
            
            return HardeningResult(
                HardeningStatus.SUCCESS,
                "Successfully hardened file systems",
                {"modified_mount_points": list(mount_points_found)}
            )
            
        except Exception as e:
            self.logger.error(f"Error hardening file systems: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error hardening file systems: {str(e)}"
            )

    def harden_network(self) -> HardeningResult:
        """Configure network security settings"""
        self.logger.info("Hardening network configuration...")
        
        try:
            network_config = {
                # TCP/IP Stack Hardening
                "net.ipv4.tcp_syncookies": "1",
                "net.ipv4.tcp_syn_retries": "2",
                "net.ipv4.tcp_synack_retries": "2",
                "net.ipv4.tcp_max_syn_backlog": "4096",
                "net.ipv4.tcp_timestamps": "0",
                "net.ipv4.tcp_rfc1337": "1",
                "net.ipv4.tcp_fin_timeout": "15",
                
                # IP Security
                "net.ipv4.conf.all.accept_redirects": "0",
                "net.ipv4.conf.default.accept_redirects": "0",
                "net.ipv4.conf.all.secure_redirects": "0",
                "net.ipv4.conf.default.secure_redirects": "0",
                "net.ipv4.conf.all.accept_source_route": "0",
                "net.ipv4.conf.default.accept_source_route": "0",
                "net.ipv4.conf.all.log_martians": "1",
                
                # IPv6 Security
                "net.ipv6.conf.all.accept_redirects": "0",
                "net.ipv6.conf.default.accept_redirects": "0",
                "net.ipv6.conf.all.accept_source_route": "0"
            }
            
            # Apply sysctl settings
            results = []
            for key, value in network_config.items():
                success, output = self.execute_command(
                    f"sysctl -w {key}={value}",
                    f"Setting network parameter: {key}"
                )
                results.append(success)
            
            # Configure host access controls
            hosts_deny = "/etc/hosts.deny"
            hosts_allow = "/etc/hosts.allow"
            
            self.backup_file(hosts_deny)
            self.backup_file(hosts_allow)
            
            if not self.dry_run:
                # Configure default deny
                with open(hosts_deny, 'w') as f:
                    f.write("ALL: ALL\n")
                
                # Configure allowed services
                with open(hosts_allow, 'w') as f:
                    f.write("sshd: 127.0.0.1\n")  # Allow local SSH
                    f.write("sshd: 192.168.0.0/16\n")  # Allow internal network
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully hardened network configuration",
                    {"applied_settings": network_config}
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to apply some network settings"
                )
                
        except Exception as e:
            self.logger.error(f"Error hardening network: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error hardening network: {str(e)}"
            )

    def harden_kernel_modules(self) -> HardeningResult:
        """Configure kernel module security"""
        self.logger.info("Hardening kernel modules...")
        
        try:
            # List of modules to blacklist
            blacklist_modules = [
                "cramfs",      # Legacy compressed RAM file system
                "freevxfs",    # Legacy file system
                "jffs2",       # Legacy flash file system
                "hfs",         # Legacy Apple file system
                "hfsplus",     # Legacy Apple file system
                "squashfs",    # Typically not needed
                "udf",         # Legacy DVD/CD file system
                "dccp",        # Datagram Congestion Control Protocol
                "sctp",        # Stream Control Transmission Protocol
                "rds",         # Reliable Datagram Sockets
                "tipc"         # Transparent Inter-Process Communication
            ]
            
            # Create blacklist configuration
            blacklist_file = "/etc/modprobe.d/security-blacklist.conf"
            self.backup_file(blacklist_file)
            
            if not self.dry_run:
                with open(blacklist_file, 'w') as f:
                    for module in blacklist_modules:
                        f.write(f"install {module} /bin/true\n")
                        f.write(f"blacklist {module}\n")
            
            # Unload modules
            results = []
            for module in blacklist_modules:
                success, output = self.execute_command(
                    f"modprobe -r {module}",
                    f"Unloading module: {module}"
                )
                results.append(success)
            
            # Update initramfs
            success, output = self.execute_command(
                "update-initramfs -u",
                "Updating initramfs"
            )
            results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully hardened kernel modules",
                    {"blacklisted_modules": blacklist_modules}
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to blacklist some kernel modules"
                )
                
        except Exception as e:
            self.logger.error(f"Error hardening kernel modules: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error hardening kernel modules: {str(e)}"
            )

    def harden_permissions(self) -> HardeningResult:
        """Set secure permissions on critical directories"""
        self.logger.info("Setting secure permissions...")
        
        try:
            # Define critical directories and their permissions
            critical_dirs = {
                "/etc": "0755",
                "/bin": "0755",
                "/sbin": "0755",
                "/usr/bin": "0755",
                "/usr/sbin": "0755",
                "/var/log": "0750",
                "/var/log/audit": "0750",
                "/etc/cron.d": "0700",
                "/etc/cron.daily": "0700",
                "/etc/cron.hourly": "0700",
                "/etc/cron.monthly": "0700",
                "/etc/cron.weekly": "0700"
            }
            
            results = []
            for directory, permission in critical_dirs.items():
                if os.path.exists(directory):
                    # Set ownership
                    success, output = self.execute_command(
                        f"chown root:root {directory}",
                        f"Setting ownership on {directory}"
                    )
                    results.append(success)
                    
                    # Set permissions
                    success, output = self.execute_command(
                        f"chmod {permission} {directory}",
                        f"Setting permissions on {directory}"
                    )
                    results.append(success)
            
            # Find and audit SUID/SGID files
            success, output = self.execute_command(
                "find / -type f -perm /6000 -ls",
                "Locating SUID/SGID files"
            )
            
            suid_files = []
            if success:
                suid_files = output.strip().split('\n')
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully set secure permissions",
                    {
                        "secured_directories": list(critical_dirs.keys()),
                        "suid_files_found": len(suid_files)
                    }
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to set some permissions"
                )
                
        except Exception as e:
            self.logger.error(f"Error setting permissions: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error setting permissions: {str(e)}"
            )
    
    def install_security_tools(self) -> HardeningResult:
        """Install and configure security tools"""
        self.logger.info("Installing security tools...")
        
        try:
            config = self.config_handler.get_section('security_tools')
            results = []
            
            # Install security packages
            for package in config.get('packages', []):
                success, output = self.execute_command(
                    f"apt-get install -y {package}",
                    f"Installing {package}"
                )
                results.append(success)
            
            # Configure fail2ban
            if 'fail2ban' in config:
                fail2ban_conf = "/etc/fail2ban/jail.local"
                self.backup_file(fail2ban_conf)
                
                if not self.dry_run:
                    with open(fail2ban_conf, 'w') as f:
                        f.write("[DEFAULT]\n")
                        for key, value in config['fail2ban'].items():
                            f.write(f"{key} = {value}\n")
                    
                    # Restart fail2ban
                    success, output = self.execute_command(
                        "systemctl restart fail2ban",
                        "Restarting fail2ban"
                    )
                    results.append(success)
            
            # Configure automatic updates
            if 'auto_upgrades' in config:
                upgrades_conf = "/etc/apt/apt.conf.d/50unattended-upgrades"
                self.backup_file(upgrades_conf)
                
                if not self.dry_run:
                    with open(upgrades_conf, 'w') as f:
                        for key, value in config['auto_upgrades'].items():
                            f.write(f'{key} "{value}";\n')
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully installed and configured security tools",
                    {"installed_packages": config.get('packages', [])}
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to install some security tools"
                )
                
        except Exception as e:
            self.logger.error(f"Error installing security tools: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error installing security tools: {str(e)}"
            )

    def harden_pam(self) -> HardeningResult:
        """Configure PAM security settings"""
        self.logger.info("Configuring PAM security settings...")
        
        try:
            # Define PAM configurations
            pam_configs = {
                '/etc/pam.d/common-auth': [
                    "auth required pam_tally2.so deny=5 unlock_time=1800",
                    "auth required pam_faildelay.so delay=4000000"
                ],
                '/etc/pam.d/common-password': [
                    "password requisite pam_pwquality.so retry=3",
                    "password required pam_pwhistory.so remember=5"
                ],
                '/etc/pam.d/common-account': [
                    "account required pam_tally2.so"
                ],
                '/etc/pam.d/login': [
                    "auth required pam_securetty.so",
                    "auth required pam_access.so"
                ]
            }
            
            results = []
            for pam_file, settings in pam_configs.items():
                if os.path.exists(pam_file):
                    self.backup_file(pam_file)
                    
                    if not self.dry_run:
                        with open(pam_file, 'r') as f:
                            content = f.readlines()
                        
                        # Add settings if not present
                        for setting in settings:
                            if not any(setting in line for line in content):
                                content.insert(0, setting + '\n')
                        
                        with open(pam_file, 'w') as f:
                            f.writelines(content)
                            
                        results.append(True)
                    
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully configured PAM settings",
                    {"configured_files": list(pam_configs.keys())}
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to configure some PAM settings"
                )
                
        except Exception as e:
            self.logger.error(f"Error configuring PAM: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error configuring PAM: {str(e)}"
            )

    def configure_time_sync(self) -> HardeningResult:
        """Configure secure time synchronization"""
        self.logger.info("Configuring time synchronization...")
        
        try:
            # Install NTP
            success, output = self.execute_command(
                "apt-get install -y ntp",
                "Installing NTP"
            )
            if not success:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    f"Failed to install NTP: {output}"
                )
            
            # Configure NTP
            ntp_conf = "/etc/ntp.conf"
            self.backup_file(ntp_conf)
            
            ntp_config = [
                "restrict default kod nomodify notrap nopeer noquery",
                "restrict -6 default kod nomodify notrap nopeer noquery",
                "restrict 127.0.0.1",
                "restrict -6 ::1",
                
                # NTP servers
                "server 0.pool.ntp.org iburst",
                "server 1.pool.ntp.org iburst",
                "server 2.pool.ntp.org iburst",
                "server 3.pool.ntp.org iburst",
                
                # Additional settings
                "disable monitor",
                "driftfile /var/lib/ntp/ntp.drift",
                "logfile /var/log/ntp.log"
            ]
            
            if not self.dry_run:
                with open(ntp_conf, 'w') as f:
                    f.write("\n".join(ntp_config) + "\n")
                
                # Restart NTP service
                success, output = self.execute_command(
                    "systemctl restart ntp",
                    "Restarting NTP service"
                )
                if not success:
                    return HardeningResult(
                        HardeningStatus.FAILED,
                        f"Failed to restart NTP service: {output}"
                    )
            
            return HardeningResult(
                HardeningStatus.SUCCESS,
                "Successfully configured time synchronization",
                {"ntp_servers": ["0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org", "3.pool.ntp.org"]}
            )
            
        except Exception as e:
            self.logger.error(f"Error configuring time sync: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error configuring time sync: {str(e)}"
            )

    def configure_process_accounting(self) -> HardeningResult:
        """Configure process accounting"""
        self.logger.info("Configuring process accounting...")
        
        try:
            # Install process accounting package
            success, output = self.execute_command(
                "apt-get install -y acct",
                "Installing process accounting"
            )
            if not success:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    f"Failed to install process accounting: {output}"
                )
            
            # Enable process accounting
            success, output = self.execute_command(
                "accton on",
                "Enabling process accounting"
            )
            if not success:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    f"Failed to enable process accounting: {output}"
                )
            
            # Enable and start the service
            commands = [
                "systemctl enable acct",
                "systemctl start acct"
            ]
            
            results = []
            for cmd in commands:
                success, output = self.execute_command(
                    cmd,
                    f"Executing: {cmd}"
                )
                results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully configured process accounting"
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to configure process accounting services"
                )
                
        except Exception as e:
            self.logger.error(f"Error configuring process accounting: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error configuring process accounting: {str(e)}"
            )

    def disable_core_dumps(self) -> HardeningResult:
        """Disable system core dumps"""
        self.logger.info("Disabling core dumps...")
        
        try:
            results = []
            
            # Configure limits.conf
            limits_conf = "/etc/security/limits.conf"
            self.backup_file(limits_conf)
            
            limits_settings = [
                "* hard core 0",
                "* soft core 0",
                "root hard core 0",
                "root soft core 0"
            ]
            
            if not self.dry_run:
                with open(limits_conf, 'a') as f:
                    f.write("\n# Disable core dumps\n")
                    f.write("\n".join(limits_settings) + "\n")
            
            # Configure sysctl
            sysctl_settings = {
                "fs.suid_dumpable": "0",
                "kernel.core_pattern": "|/bin/false"
            }
            
            for key, value in sysctl_settings.items():
                success, output = self.execute_command(
                    f"sysctl -w {key}={value}",
                    f"Setting {key}"
                )
                results.append(success)
            
            # Disable systemd coredump
            success, output = self.execute_command(
                "systemctl mask systemd-coredump.socket",
                "Masking systemd coredump socket"
            )
            results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully disabled core dumps",
                    {
                        "limits_conf": limits_settings,
                        "sysctl_settings": sysctl_settings
                    }
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to disable some core dump settings"
                )
                
        except Exception as e:
            self.logger.error(f"Error disabling core dumps: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error disabling core dumps: {str(e)}"
            )
    
    def secure_usb_storage(self) -> HardeningResult:
        """Secure USB storage access"""
        self.logger.info("Securing USB storage...")
        
        try:
            # Create modprobe configuration
            modprobe_conf = "/etc/modprobe.d/usb-storage.conf"
            self.backup_file(modprobe_conf)
            
            config_content = [
                "# Disable USB storage for security",
                "install usb-storage /bin/true",
                "blacklist usb-storage",
                "blacklist uas",  # USB Attached SCSI
                "blacklist sd_mod"  # SCSI disk support
            ]
            
            if not self.dry_run:
                with open(modprobe_conf, 'w') as f:
                    f.write("\n".join(config_content) + "\n")
            
            # Unload modules
            modules = ['usb-storage', 'uas']
            results = []
            
            for module in modules:
                success, output = self.execute_command(
                    f"modprobe -r {module}",
                    f"Unloading {module} module"
                )
                results.append(success)
            
            # Update initramfs
            success, output = self.execute_command(
                "update-initramfs -u",
                "Updating initramfs"
            )
            results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully secured USB storage",
                    {"disabled_modules": modules}
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to secure some USB storage components"
                )
            
        except Exception as e:
            self.logger.error(f"Error securing USB storage: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error securing USB storage: {str(e)}"
            )

    def harden_cron(self) -> HardeningResult:
        """Secure cron configuration"""
        self.logger.info("Hardening cron configuration...")
        
        try:
            results = []
            
            # Set permissions on cron directories
            cron_dirs = {
                "/etc/cron.d": "700",
                "/etc/cron.daily": "700",
                "/etc/cron.hourly": "700",
                "/etc/cron.monthly": "700",
                "/etc/cron.weekly": "700",
                "/var/spool/cron": "700"
            }
            
            for directory, permission in cron_dirs.items():
                if os.path.exists(directory):
                    # Set ownership
                    success, output = self.execute_command(
                        f"chown root:root {directory}",
                        f"Setting ownership on {directory}"
                    )
                    results.append(success)
                    
                    # Set permissions
                    success, output = self.execute_command(
                        f"chmod {permission} {directory}",
                        f"Setting permissions on {directory}"
                    )
                    results.append(success)
            
            # Configure cron access
            cron_files = {
                "/etc/cron.allow": ("600", "root\n"),
                "/etc/cron.deny": ("600", "ALL\n"),
                "/etc/at.allow": ("600", "root\n"),
                "/etc/at.deny": ("600", "ALL\n")
            }
            
            for file_path, (permission, content) in cron_files.items():
                self.backup_file(file_path)
                
                if not self.dry_run:
                    # Write content
                    with open(file_path, 'w') as f:
                        f.write(content)
                    
                    # Set ownership and permissions
                    success, _ = self.execute_command(
                        f"chown root:root {file_path}",
                        f"Setting ownership on {file_path}"
                    )
                    results.append(success)
                    
                    success, _ = self.execute_command(
                        f"chmod {permission} {file_path}",
                        f"Setting permissions on {file_path}"
                    )
                    results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully hardened cron configuration",
                    {
                        "secured_directories": list(cron_dirs.keys()),
                        "secured_files": list(cron_files.keys())
                    }
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to harden some cron settings"
                )
                
        except Exception as e:
            self.logger.error(f"Error hardening cron: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error hardening cron: {str(e)}"
            )

    def secure_boot(self) -> HardeningResult:
        """Secure boot configuration"""
        self.logger.info("Securing boot configuration...")
        
        try:
            results = []
            
            # Configure GRUB
            grub_config = "/etc/default/grub"
            self.backup_file(grub_config)
            
            grub_settings = {
                'GRUB_CMDLINE_LINUX': (
                    'audit=1 audit_backlog_limit=8192 '
                    'init_on_alloc=1 init_on_free=1 '
                    'page_alloc.shuffle=1 pti=on '
                    'randomize_kstack_offset=on slab_nomerge=yes '
                    'slub_debug=FZP mce=0 vsyscall=none '
                    'lockdown=confidentiality quiet'
                ),
                'GRUB_DISABLE_RECOVERY': 'true',
                'GRUB_DISABLE_SUBMENU': 'true',
                'GRUB_ENABLE_BLSCFG': 'true',
                'GRUB_TIMEOUT': '5',
                'GRUB_DISABLE_OS_PROBER': 'true'
            }
            
            if not self.dry_run:
                with open(grub_config, 'r') as f:
                    lines = f.readlines()
                
                # Update existing settings and track what's been set
                new_lines = []
                set_settings = set()
                
                for line in lines:
                    line_stripped = line.strip()
                    if line_stripped and not line_stripped.startswith('#'):
                        key = line_stripped.split('=')[0]
                        if key in grub_settings:
                            new_lines.append(f'{key}="{grub_settings[key]}"\n')
                            set_settings.add(key)
                            continue
                    new_lines.append(line)
                
                # Add any missing settings
                for key, value in grub_settings.items():
                    if key not in set_settings:
                        new_lines.append(f'{key}="{value}"\n')
                
                with open(grub_config, 'w') as f:
                    f.writelines(new_lines)
                
                # Update GRUB
                success, output = self.execute_command(
                    "update-grub",
                    "Updating GRUB configuration"
                )
                results.append(success)
            
            # Secure boot directory
            boot_security = [
                ("chmod 600 /boot/grub/grub.cfg", "Securing GRUB config file"),
                ("chown root:root /boot/grub/grub.cfg", "Setting GRUB config ownership"),
                ("chmod 700 /boot", "Securing boot directory"),
                ("chown root:root /boot", "Setting boot directory ownership")
            ]
            
            for cmd, desc in boot_security:
                success, output = self.execute_command(cmd, desc)
                results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully secured boot configuration",
                    {"grub_settings": grub_settings}
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to secure some boot components"
                )
                
        except Exception as e:
            self.logger.error(f"Error securing boot: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error securing boot: {str(e)}"
            )

    def secure_package_management(self) -> HardeningResult:
        """Secure package management configuration"""
        self.logger.info("Securing package management...")
        
        try:
            results = []
            
            # Install required packages
            packages = [
                "unattended-upgrades",
                "apt-listchanges",
                "needrestart"
            ]
            
            for package in packages:
                success, output = self.execute_command(
                    f"apt-get install -y {package}",
                    f"Installing {package}"
                )
                results.append(success)
            
            # Configure unattended upgrades
            upgrades_conf = "/etc/apt/apt.conf.d/50unattended-upgrades"
            self.backup_file(upgrades_conf)
            
            upgrade_settings = [
                'Unattended-Upgrade::Remove-Unused-Dependencies "true";',
                'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";',
                'Unattended-Upgrade::AutoFixInterruptedDpkg "true";',
                'Unattended-Upgrade::MinimalSteps "true";',
                'Unattended-Upgrade::InstallOnShutdown "false";',
                'Unattended-Upgrade::Mail "root";',
                'Unattended-Upgrade::MailReport "on-change";',
                'Unattended-Upgrade::SyslogEnable "true";',
                'Unattended-Upgrade::SyslogFacility "daemon";',
                'Unattended-Upgrade::Automatic-Reboot "false";',
                'Unattended-Upgrade::Automatic-Reboot-Time "02:00";',
                'Unattended-Upgrade::Keep-Debs-After "false";'
            ]
            
            if not self.dry_run:
                with open(upgrades_conf, 'w') as f:
                    f.write("\n".join(upgrade_settings) + "\n")
            
            # Configure automatic updates
            auto_upgrades_conf = "/etc/apt/apt.conf.d/20auto-upgrades"
            self.backup_file(auto_upgrades_conf)
            
            auto_upgrade_settings = [
                'APT::Periodic::Update-Package-Lists "1";',
                'APT::Periodic::Unattended-Upgrade "1";',
                'APT::Periodic::AutocleanInterval "7";',
                'APT::Periodic::Download-Upgradeable-Packages "1";',
                'APT::Periodic::Download-Upgradeable-Packages-Debdelta "1";',
                'APT::Periodic::Clean-Installed-Packages "1";'
            ]
            
            if not self.dry_run:
                with open(auto_upgrades_conf, 'w') as f:
                    f.write("\n".join(auto_upgrade_settings) + "\n")
            
            # Enable services
            services = [
                "unattended-upgrades",
                "apt-daily.timer",
                "apt-daily-upgrade.timer"
            ]
            
            for service in services:
                success, output = self.execute_command(
                    f"systemctl enable {service}",
                    f"Enabling {service}"
                )
                results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully secured package management",
                    {
                        "installed_packages": packages,
                        "enabled_services": services
                    }
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to secure some package management components"
                )
                
        except Exception as e:
            self.logger.error(f"Error securing package management: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error securing package management: {str(e)}"
            )
    
    def harden_system_access(self) -> HardeningResult:
        """Harden system access controls"""
        self.logger.info("Hardening system access...")
        
        try:
            results = []
            
            # Configure login.defs
            login_defs = "/etc/login.defs"
            self.backup_file(login_defs)
            
            login_settings = {
                'PASS_MAX_DAYS': '90',
                'PASS_MIN_DAYS': '7',
                'PASS_WARN_AGE': '7',
                'LOGIN_RETRIES': '3',
                'LOGIN_TIMEOUT': '60',
                'UMASK': '027',
                'ENCRYPT_METHOD': 'SHA512',
                'SHA_CRYPT_MIN_ROUNDS': '5000',
                'SHA_CRYPT_MAX_ROUNDS': '100000',
                'FAIL_DELAY': '4',
                'LOG_OK_LOGINS': 'yes',
                'LOG_UNKFAIL_ENAB': 'yes',
                'SYSLOG_SU_ENAB': 'yes',
                'SYSLOG_SG_ENAB': 'yes'
            }
            
            if not self.dry_run:
                with open(login_defs, 'r') as f:
                    lines = f.readlines()
                
                new_lines = []
                set_settings = set()
                
                for line in lines:
                    line_stripped = line.strip()
                    if line_stripped and not line_stripped.startswith('#'):
                        key = line_stripped.split()[0]
                        if key in login_settings:
                            new_lines.append(f"{key}\t{login_settings[key]}\n")
                            set_settings.add(key)
                            continue
                    new_lines.append(line)
                
                # Add missing settings
                for key, value in login_settings.items():
                    if key not in set_settings:
                        new_lines.append(f"{key}\t{value}\n")
                
                with open(login_defs, 'w') as f:
                    f.writelines(new_lines)
            
            # Configure secure TTY
            securetty = "/etc/securetty"
            self.backup_file(securetty)
            
            # Only allow console and local TTY access
            allowed_ttys = [
                "console",
                "tty1",
                "tty2",
                "tty3",
                "tty4"
            ]
            
            if not self.dry_run:
                with open(securetty, 'w') as f:
                    f.write("\n".join(allowed_ttys) + "\n")
            
            # Configure profile security settings
            profile_security = "/etc/profile.d/security.sh"
            security_settings = [
                "# Security settings",
                "umask 027",
                "TMOUT=900",
                "readonly TMOUT",
                "export TMOUT",
                "export HISTCONTROL=ignoredups",
                "export HISTSIZE=1000",
                "export HISTFILESIZE=1000",
                "readonly HISTSIZE",
                "readonly HISTFILESIZE"
            ]
            
            if not self.dry_run:
                with open(profile_security, 'w') as f:
                    f.write("\n".join(security_settings) + "\n")
                
                success, _ = self.execute_command(
                    f"chmod 644 {profile_security}",
                    "Setting permissions on security profile"
                )
                results.append(success)
            
            # Configure access.conf
            access_conf = "/etc/security/access.conf"
            self.backup_file(access_conf)
            
            access_rules = [
                "# Allow root only from console",
                "+:root:console",
                "+:root:tty1",
                "-:root:ALL",
                # Allow users only from local network
                "+:ALL:LOCAL",
                "-:ALL:ALL"
            ]
            
            if not self.dry_run:
                with open(access_conf, 'w') as f:
                    f.write("\n".join(access_rules) + "\n")
            
            # Set permissions on security files
            security_files = {
                "/etc/security": "755",
                "/etc/security/access.conf": "644",
                "/etc/security/limits.conf": "644",
                "/etc/security/pwquality.conf": "644"
            }
            
            for file_path, permission in security_files.items():
                if os.path.exists(file_path):
                    success, _ = self.execute_command(
                        f"chmod {permission} {file_path}",
                        f"Setting permissions on {file_path}"
                    )
                    results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully hardened system access",
                    {
                        "login_settings": login_settings,
                        "allowed_ttys": allowed_ttys,
                        "security_files": list(security_files.keys())
                    }
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to harden some system access controls"
                )
                
        except Exception as e:
            self.logger.error(f"Error hardening system access: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error hardening system access: {str(e)}"
            )

    def harden_memory_protection(self) -> HardeningResult:
        """Configure memory protection mechanisms"""
        self.logger.info("Configuring memory protection...")
        
        try:
            results = []
            
            # Configure sysctl memory protection settings
            memory_settings = {
                # ASLR configuration
                "kernel.randomize_va_space": "2",
                
                # Memory protection
                "vm.mmap_min_addr": "65536",
                "kernel.kptr_restrict": "2",
                "kernel.yama.ptrace_scope": "1",
                "kernel.perf_event_paranoid": "3",
                
                # Dirty memory management
                "vm.dirty_ratio": "10",
                "vm.dirty_background_ratio": "5",
                "vm.dirty_expire_centisecs": "500",
                "vm.dirty_writeback_centisecs": "100",
                
                # OOM killer configuration
                "vm.oom_kill_allocating_task": "1",
                "vm.panic_on_oom": "0",
                
                # Memory overcommit settings
                "vm.overcommit_memory": "0",
                "vm.overcommit_ratio": "50",
                
                # Swap settings
                "vm.swappiness": "10",
                
                # Additional protections
                "kernel.dmesg_restrict": "1",
                "kernel.unprivileged_bpf_disabled": "1",
                "net.core.bpf_jit_harden": "2"
            }
            
            for key, value in memory_settings.items():
                success, output = self.execute_command(
                    f"sysctl -w {key}={value}",
                    f"Setting {key}"
                )
                results.append(success)
                
                if not self.dry_run:
                    # Add to sysctl.conf for persistence
                    with open("/etc/sysctl.d/80-memory-protection.conf", 'a') as f:
                        f.write(f"{key} = {value}\n")
            
            # Configure PAM limits for memory
            limits_conf = "/etc/security/limits.d/memory-limits.conf"
            self.backup_file(limits_conf)
            
            memory_limits = [
                "# Memory limits",
                "*          soft    nproc           1024",
                "*          hard    nproc           2048",
                "*          soft    nofile          1024",
                "*          hard    nofile          65535",
                "*          soft    memlock         64",
                "*          hard    memlock         64",
                "root       soft    nproc           unlimited",
                "root       hard    nproc           unlimited",
                "root       soft    nofile          unlimited",
                "root       hard    nofile          unlimited"
            ]
            
            if not self.dry_run:
                with open(limits_conf, 'w') as f:
                    f.write("\n".join(memory_limits) + "\n")
            
            # Configure additional memory protection in GRUB
            grub_memory_params = (
                "page_alloc.shuffle=1 "
                "slub_debug=F "
                "init_on_alloc=1 "
                "init_on_free=1 "
                "pti=on "
                "vsyscall=none "
                "debugfs=off"
            )
            
            # Append memory protection parameters to GRUB
            grub_config = "/etc/default/grub"
            if os.path.exists(grub_config):
                with open(grub_config, 'r') as f:
                    lines = f.readlines()
                
                updated_lines = []
                cmdline_updated = False
                
                for line in lines:
                    if line.startswith('GRUB_CMDLINE_LINUX_DEFAULT='):
                        # Add memory protection parameters
                        line = line.rstrip('\n').rstrip('"') + " " + grub_memory_params + '"\n'
                        cmdline_updated = True
                    updated_lines.append(line)
                
                if not cmdline_updated:
                    updated_lines.append(f'GRUB_CMDLINE_LINUX_DEFAULT="{grub_memory_params}"\n')
                
                if not self.dry_run:
                    with open(grub_config, 'w') as f:
                        f.writelines(updated_lines)
                    
                    # Update GRUB
                    success, output = self.execute_command(
                        "update-grub",
                        "Updating GRUB configuration"
                    )
                    results.append(success)
            
            if all(results):
                return HardeningResult(
                    HardeningStatus.SUCCESS,
                    "Successfully configured memory protection",
                    {
                        "sysctl_settings": memory_settings,
                        "grub_parameters": grub_memory_params
                    }
                )
            else:
                return HardeningResult(
                    HardeningStatus.FAILED,
                    "Failed to configure some memory protection settings"
                )
                
        except Exception as e:
            self.logger.error(f"Error configuring memory protection: {e}")
            return HardeningResult(
                HardeningStatus.FAILED,
                f"Error configuring memory protection: {str(e)}"
            )
   
    def harden_system(self) -> List[HardeningResult]:
        """Execute all hardening operations"""
        self.logger.info("Starting system hardening...")
        
        operations = [
            ('File Permissions', self.harden_file_permissions),
            ('SSH Configuration', self.harden_ssh),
            ('Firewall Configuration', self.harden_firewall),
            ('Sysctl Settings', self.harden_sysctl),
            ('Password Policies', self.harden_password_policy),
            ('Audit Logging', self.harden_audit_logging),
            ('System Services', self.harden_services),
            ('User Accounts', self.harden_user_accounts),
            ('File Systems', self.harden_file_systems),
            ('Network Settings', self.harden_network),
            ('Kernel Modules', self.harden_kernel_modules),
            ('Directory Permissions', self.harden_permissions),
            ('Security Tools', self.install_security_tools),
            ('PAM Configuration', self.harden_pam),
            ('Time Synchronization', self.configure_time_sync),
            ('Process Accounting', self.configure_process_accounting),
            ('Core Dumps', self.disable_core_dumps),
            ('USB Storage', self.secure_usb_storage),
            ('Cron Configuration', self.harden_cron),
            ('Boot Security', self.secure_boot),
            ('Package Management', self.secure_package_management),
            ('System Access', self.harden_system_access),
            ('Memory Protection', self.harden_memory_protection)
        ]
        
        results = []
        for name, operation in operations:
            self.logger.info(f"Starting {name} hardening...")
            try:
                result = operation()
                results.append(result)
                self.logger.info(
                    f"Completed {name} hardening - Status: {result.status.name}"
                )
            except Exception as e:
                self.logger.error(f"Error during {name} hardening: {e}")
                results.append(HardeningResult(
                    HardeningStatus.FAILED,
                    f"Error during {name} hardening: {str(e)}"
                ))
        
        return results


# def main():
#     """Example usage of SystemHardener"""
#     from config_handler import ConfigurationHandler
    
#     # Initialize configuration handler
#     config_handler = ConfigurationHandler()
    
#     try:
#         # Load configuration
#         config_handler.load_config('system_hardening_config.yaml')
        
#         # Initialize hardener
#         hardener = SystemHardener(
#             config_handler,
#             dry_run=True  # Set to False for actual execution
#         )
        
#         # Execute hardening
#         results = hardener.harden_system()
        
#         # Print results
#         print("\nHardening Results:")
#         for result in results:
#             print(f"Status: {result.status.name}")
#             print(f"Message: {result.message}")
#             if result.details:
#                 print(f"Details: {result.details}")
#             print("-" * 50)
            
#     except Exception as e:
#         print(f"Error during system hardening: {e}")
#         sys.exit(1)

# if __name__ == "__main__":
#     main()