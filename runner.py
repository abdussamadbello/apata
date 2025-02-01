#!/usr/bin/env python3

import os
import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json
import signal
from contextlib import contextmanager
import time

from apata.config_handler import ConfigurationHandler
from apata.system_hardener import SystemHardener, HardeningStatus, HardeningResult

class SystemHardeningRunner:
    """Main runner class for system hardening operations"""
    
    def __init__(self):
        self.args = self._parse_arguments()
        self.logger = self._setup_logging()
        self.start_time = datetime.now()
        self.results_file = Path(self.args.output_dir) / f"hardening_results_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"

    def _parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="System Hardening Tool",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        parser.add_argument(
            "--config",
            help="Path to configuration file",
            default="/etc/system_hardening/config.yaml"
        )
        
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Perform a dry run without making changes"
        )
        
        parser.add_argument(
            "--output-dir",
            help="Directory for output files",
            default="/var/log/system_hardening"
        )
        
        parser.add_argument(
            "--log-level",
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default='INFO',
            help="Set the logging level"
        )
        
        parser.add_argument(
            "--skip-backup",
            action="store_true",
            help="Skip creating backups before modifications"
        )
        
        parser.add_argument(
            "--sections",
            nargs="+",
            help="Specific sections to harden (default: all)"
        )
        
        parser.add_argument(
            "--timeout",
            type=int,
            default=3600,
            help="Timeout in seconds for the entire hardening process"
        )
        
        parser.add_argument(
            "--no-rollback",
            action="store_true",
            help="Disable automatic rollback on failure"
        )
        
        parser.add_argument(
            "--report-format",
            choices=['json', 'yaml', 'text'],
            default='json',
            help="Output format for the hardening report"
        )
        
        return parser.parse_args()

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration"""
        logger = logging.getLogger("SystemHardening")
        logger.setLevel(getattr(logging, self.args.log_level))
        
        # Create output directory if it doesn't exist
        Path(self.args.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Create formatters and handlers
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler
        log_file = Path(self.args.output_dir) / f"system_hardening_{self.start_time.strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger

    @contextmanager
    def _timeout_handler(self, timeout: int):
        """Handle timeout for the hardening process"""
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Hardening process timed out after {timeout} seconds")

        # Set up the timeout
        original_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        
        try:
            yield
        finally:
            # Restore original handler and cancel alarm
            signal.alarm(0)
            signal.signal(signal.SIGALRM, original_handler)

    def _save_results(self, results: Dict[str, Any]) -> None:
        """Save hardening results to file"""
        try:
            # Create output directory if it doesn't exist
            self.results_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Add metadata to results
            results.update({
                "timestamp": self.start_time.isoformat(),
                "duration": str(datetime.now() - self.start_time),
                "command_args": vars(self.args)
            })
            
            # Save results
            with self.results_file.open('w') as f:
                if self.args.report_format == 'json':
                    json.dump(results, f, indent=2)
                elif self.args.report_format == 'yaml':
                    import yaml
                    yaml.dump(results, f)
                else:  # text format
                    self._write_text_report(f, results)
                    
            self.logger.info(f"Results saved to {self.results_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

    def _write_text_report(self, file, results: Dict[str, Any]) -> None:
        """Write results in text format"""
        file.write("System Hardening Report\n")
        file.write("=" * 50 + "\n\n")
        
        file.write(f"Timestamp: {results['timestamp']}\n")
        file.write(f"Duration: {results['duration']}\n")
        file.write("\nResults by Section:\n")
        
        for section, result in results['sections'].items():
            file.write(f"\n{section}:\n")
            file.write("-" * len(section) + "\n")
            file.write(f"Status: {result['status']}\n")
            file.write(f"Message: {result['message']}\n")
            if 'details' in result:
                file.write("Details:\n")
                for key, value in result['details'].items():
                    file.write(f"  {key}: {value}\n")

    def run(self) -> int:
        """Execute the hardening process"""
        try:
            self.logger.info("Starting system hardening process...")
            
            # Check if running as root
            if os.geteuid() != 0:
                self.logger.error("This script must be run as root")
                return 1
            
            # Load configuration
            config_handler = ConfigurationHandler(self.logger)
            config_handler.load_config(self.args.config)
            
            # Initialize hardener
            hardener = SystemHardener(
                config_handler=config_handler,
                logger=self.logger,
                dry_run=self.args.dry_run
            )
            
            # Execute hardening with timeout
            with self._timeout_handler(self.args.timeout):
                results = hardener.harden_system()
            
            # Process results
            processed_results = {
                "status": "success" if all(r.status == HardeningStatus.SUCCESS for r in results) else "failed",
                "sections": {
                    f"Section_{i}": {
                        "status": r.status.name,
                        "message": r.message,
                        "details": r.details
                    } for i, r in enumerate(results, 1)
                }
            }
            
            # Save results
            self._save_results(processed_results)
            
            # Final status
            if processed_results["status"] == "success":
                self.logger.info("System hardening completed successfully")
                return 0
            else:
                self.logger.error("System hardening completed with failures")
                return 1
                
        except TimeoutError as e:
            self.logger.error(f"Timeout error: {e}")
            return 2
        except KeyboardInterrupt:
            self.logger.error("Process interrupted by user")
            return 3
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return 4

def main():
    """Main entry point"""
    try:
        runner = SystemHardeningRunner()
        sys.exit(runner.run())
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(5)

if __name__ == "__main__":
    main()