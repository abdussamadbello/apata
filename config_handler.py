import os
from typing import Dict, Any, Optional
from pathlib import Path
import shutil
from datetime import datetime
import logging
from ruamel.yaml import YAML, YAMLError

class ConfigurationHandler:
    """Handles loading, validation, and management of system hardening configuration"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the configuration handler
        
        Args:
            logger: Optional logger instance. If not provided, creates a new one.
        """
        self.logger = logger or self._setup_logger()
        self.yaml = YAML(typ='safe')
        self.config: Dict[str, Any] = {}
        
    def _setup_logger(self) -> logging.Logger:
        """Set up a logger if none is provided"""
        logger = logging.getLogger("ConfigurationHandler")
        logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        return logger

    def load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from a YAML file
        
        Args:
            config_file: Path to the YAML configuration file
            
        Returns:
            Dict containing the configuration
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            YAMLError: If YAML parsing fails
            ValueError: If configuration validation fails
        """
        config_path = Path(config_file)
        
        try:
            if not config_path.exists():
                raise FileNotFoundError(f"Configuration file not found: {config_file}")
                
            # Create backup before loading
            self._backup_config(config_path)
            
            # Load and parse YAML
            with config_path.open('r') as f:
                self.config = self.yaml.load(f)
                
            # Validate configuration
            self._validate_config(self.config)
            
            self.logger.info(f"Successfully loaded configuration from {config_file}")
            return self.config
            
        except YAMLError as e:
            self.logger.error(f"YAML parsing error in {config_file}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error loading configuration from {config_file}: {e}")
            raise

    def save_config(self, filename: str, create_backup: bool = True) -> None:
        """Save current configuration to a YAML file
        
        Args:
            filename: Path to save the configuration file
            create_backup: Whether to create a backup of existing file
            
        Raises:
            IOError: If writing configuration fails
        """
        yaml = YAML()
        yaml.indent(mapping=2, sequence=4, offset=2)
        
        try:
            file_path = Path(filename)
            
            # Create backup if file exists and backup is requested
            if create_backup and file_path.exists():
                self._backup_config(file_path)
            
            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with file_path.open('w') as f:
                yaml.dump(self.config, f)
                
            self.logger.info(f"Configuration saved to {filename}")
            
        except Exception as e:
            self.logger.error(f"Error saving configuration to {filename}: {e}")
            raise

    def update_config(self, updates: Dict[str, Any], save: bool = True) -> None:
        """Update configuration with new values
        
        Args:
            updates: Dictionary containing configuration updates
            save: Whether to save updates to file immediately
            
        Raises:
            ValueError: If updated configuration is invalid
        """
        try:
            # Deep merge updates into current config
            self._deep_update(self.config, updates)
            
            # Validate updated configuration
            self._validate_config(self.config)
            
            if save:
                self.save_config(self.config.get('config_file', 'system_hardening_config.yaml'))
                
            self.logger.info("Configuration updated successfully")
            
        except Exception as e:
            self.logger.error(f"Error updating configuration: {e}")
            raise

    def _backup_config(self, file_path: Path) -> None:
        """Create a backup of configuration file
        
        Args:
            file_path: Path to the configuration file to backup
        """
        if file_path.exists():
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = file_path.with_suffix(f'.yaml.backup_{timestamp}')
            shutil.copy2(file_path, backup_path)
            self.logger.info(f"Created backup at {backup_path}")

    def _deep_update(self, original: Dict[str, Any], updates: Dict[str, Any]) -> None:
        """Recursively update nested dictionaries
        
        Args:
            original: Original dictionary to update
            updates: Dictionary containing updates
        """
        for key, value in updates.items():
            if isinstance(value, dict) and key in original and isinstance(original[key], dict):
                self._deep_update(original[key], value)
            else:
                original[key] = value

    def _validate_config(self, config: Dict[str, Any]) -> None:
        """Validate configuration structure and values
        
        Args:
            config: Configuration dictionary to validate
            
        Raises:
            ValueError: If configuration is invalid
        """
        required_sections = [
            'file_permissions',
            'ssh_config',
            'firewall',
            'sysctl',
            'password_policy',
            'audit_logging',
            'services',
            'security_tools'
        ]
        
        # Check for required top-level sections
        missing_sections = [
            section for section in required_sections 
            if section not in config
        ]
        
        if missing_sections:
            raise ValueError(
                f"Missing required configuration sections: {', '.join(missing_sections)}"
            )
        
        # Validate specific sections
        self._validate_file_permissions(config.get('file_permissions', {}))
        self._validate_ssh_config(config.get('ssh_config', {}))
        # Add additional section validators as needed

    def _validate_file_permissions(self, config: Dict[str, Any]) -> None:
        """Validate file permissions configuration
        
        Args:
            config: File permissions configuration section
            
        Raises:
            ValueError: If configuration is invalid
        """
        if not isinstance(config.get('critical_files'), dict):
            raise ValueError("file_permissions.critical_files must be a dictionary")
            
        for file_path, settings in config['critical_files'].items():
            required_keys = {'mode', 'owner', 'group'}
            if not all(key in settings for key in required_keys):
                raise ValueError(
                    f"Missing required keys {required_keys} for file {file_path}"
                )

    def _validate_ssh_config(self, config: Dict[str, Any]) -> None:
        """Validate SSH configuration
        
        Args:
            config: SSH configuration section
            
        Raises:
            ValueError: If configuration is invalid
        """
        if not isinstance(config.get('settings'), dict):
            raise ValueError("ssh_config.settings must be a dictionary")
            
        required_settings = {
            'PermitRootLogin',
            'PasswordAuthentication',
            'X11Forwarding'
        }
        
        missing_settings = required_settings - set(config['settings'].keys())
        if missing_settings:
            raise ValueError(
                f"Missing required SSH settings: {', '.join(missing_settings)}"
            )

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get a specific configuration section
        
        Args:
            section: Name of the configuration section
            
        Returns:
            Dictionary containing the section configuration
            
        Raises:
            KeyError: If section doesn't exist
        """
        if section not in self.config:
            raise KeyError(f"Configuration section not found: {section}")
        return self.config[section]

    def get_value(self, path: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation
        
        Args:
            path: Configuration path (e.g., 'ssh_config.settings.PermitRootLogin')
            default: Default value if path doesn't exist
            
        Returns:
            Configuration value or default
        """
        current = self.config
        for key in path.split('.'):
            if isinstance(current, dict):
                current = current.get(key, default)
            else:
                return default
        return current

# def main():
#     """Example usage of ConfigurationHandler"""
#     # Initialize handler
#     config_handler = ConfigurationHandler()
    
#     try:
#         # Load configuration
#         config = config_handler.load_config('system_hardening_config.yaml')
        
#         # Get specific sections
#         ssh_config = config_handler.get_section('ssh_config')
#         print("SSH Configuration:", ssh_config)
        
#         # Get specific values
#         permit_root = config_handler.get_value('ssh_config.settings.PermitRootLogin')
#         print("PermitRootLogin setting:", permit_root)
        
#         # Update configuration
#         updates = {
#             'ssh_config': {
#                 'settings': {
#                     'PermitRootLogin': 'no',
#                     'PasswordAuthentication': 'no'
#                 }
#             }
#         }
#         config_handler.update_config(updates)
        
#     except Exception as e:
#         print(f"Error: {e}")

# if __name__ == "__main__":