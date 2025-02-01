import os
import sys
import subprocess
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from pathlib import Path
import shutil
import grp
import pwd
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