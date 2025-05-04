#!/usr/bin/env python3
import argparse
import json
import yaml
import csv
import os
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

# Configure logging to file only (completely silent in terminal)
logging.basicConfig(
    level=logging.ERROR,
    filename='./reports/ciat_errors.log',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filemode='w'
)
# Completely disable all logging propagation
logger = logging.getLogger(__name__)
logger.propagate = False
logging.getLogger().handlers = []  # Remove default handlers

# Import all audit modules
from ssh_audit import SSHAudit
from file_permissions_audit import FilePermissionsAudit
from firewall_rules_audit import FirewallRulesAudit
from running_services_audit import RunningServicesAudit
from ports_check_audit import OpenPortsAudit
from package_inventory import SW_Inventory
from users_sudo_audit import SudoAudit

# Create reports directory if it doesn't exist
os.makedirs("./reports", exist_ok=True)

def generate_timestamp() -> str:
    """Generate timestamp for filename (YYYYMMDD_HHMMSS)"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def run_audit(audit_class, **kwargs) -> Optional[Dict]:
    """Run an audit module and return its report or None if failed"""
    try:
        # Create a completely silent environment
        with open(os.devnull, 'w') as devnull:
            import sys
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = devnull
            sys.stderr = devnull
            
            # Also silence the module's logger
            module_logger = logging.getLogger(audit_class.__module__)
            module_logger.propagate = False
            module_logger.handlers = []
            
            try:
                audit = audit_class(**kwargs)
                result = audit.audit()
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
        return result
    except Exception as e:
        logger.error(f"Audit {audit_class.__name__} failed: {str(e)}")
        return None
def generate_summary(reports: Dict[str, Dict]) -> str:
    """Generate the summary table from all audit reports"""
    summary = []
    for name, report in reports.items():
        if report is None:
            summary.append(f"- {name}: ❌ (Failed - check error log)")
            continue
        
        if name == "SSH":
            score = report.get("score", "N/A")
            summary.append(f"- SSH Audit: ✅ (Score: {score}/100)")
        else:
            issues = sum(len(v) for v in report.values() if isinstance(v, list))
            status = "⚠️" if issues else "✅"
            summary.append(f"- {name}: {status} ({issues} issues found)")
    
    return "=== CIAT Report Summary ===\n" + "\n".join(summary)

def save_output(reports: Dict, output_path: str, fmt: str = "text"):
    """Save reports to file in specified format"""
    timestamp = generate_timestamp()
    
    if fmt == "json":
        if not output_path:
            output_path = f"./reports/CIAT_{timestamp}.json"
        with open(output_path, "w") as f:
            json.dump(reports, f, indent=4)
    elif fmt == "yaml":
        if not output_path:
            output_path = f"./reports/CIAT_{timestamp}.yaml"
        with open(output_path, "w") as f:
            yaml.dump(reports, f, default_flow_style=False)
    elif fmt == "csv":
        if not output_path:
            output_path = f"./reports/CIAT_{timestamp}.csv"
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Audit", "Key", "Value"])
            for audit, data in reports.items():
                if data:
                    for key, value in data.items():
                        if isinstance(value, list):
                            writer.writerow([audit, key, "; ".join(value)])
                        else:
                            writer.writerow([audit, key, str(value)])
    else:  # text
        if not output_path:
            output_path = f"./reports/CIAT_{timestamp}.txt"
        with open(output_path, "w") as f:
            # Save both summary and detailed report
            f.write(generate_summary(reports) + "\n\n")
            for audit, data in reports.items():
                if data:
                    f.write(f"=== {audit} Details ===\n")
                    for key, value in data.items():
                        f.write(f"{key}:\n")
                        if isinstance(value, list):
                            for item in value:
                                f.write(f"  - {item}\n")
                        else:
                            f.write(f"  {value}\n")
            # Also save errors if any
            if os.path.exists('./reports/ciat_errors.log'):
                with open('./reports/ciat_errors.log', 'r') as err_file:
                    f.write("\n=== Errors ===\n")
                    f.write(err_file.read())

def main():
    parser = argparse.ArgumentParser(description="CIAT - Comprehensive Infrastructure Audit Tool")
    
    # Individual audit flags
    parser.add_argument("--ssh", action="store_true", help="Run SSH audit")
    parser.add_argument("--files", action="store_true", help="Run file permissions audit")
    parser.add_argument("--firewall", action="store_true", help="Run firewall rules audit")
    parser.add_argument("--services", action="store_true", help="Run running services audit")
    parser.add_argument("--ports", action="store_true", help="Run open ports audit")
    parser.add_argument("--packages", action="store_true", help="Run software inventory audit")
    parser.add_argument("--users", action="store_true", help="Run sudo/users audit")
    
    # Combined flags
    parser.add_argument("--all", action="store_true", help="Run all audits")
    
    # Output options
    parser.add_argument("--json", action="store_true", help="Save output as JSON")
    parser.add_argument("--yaml", action="store_true", help="Save output as YAML")
    parser.add_argument("--csv", action="store_true", help="Save output as CSV")
    parser.add_argument("--output", type=str, help="Custom output file path")
    
    args = parser.parse_args()
    
    # Determine which audits to run
    audits_to_run = []
    if args.all:
        audits_to_run = [
            ("SSH", SSHAudit),
            ("File Permissions", FilePermissionsAudit),
            ("Firewall Rules", FirewallRulesAudit),
            ("Running Services", RunningServicesAudit),
            ("Open Ports", OpenPortsAudit),
            ("Software Inventory", SW_Inventory),
            ("Sudo/Users", SudoAudit)
        ]
    else:
        if args.ssh: audits_to_run.append(("SSH", SSHAudit))
        if args.files: audits_to_run.append(("File Permissions", FilePermissionsAudit))
        if args.firewall: audits_to_run.append(("Firewall Rules", FirewallRulesAudit))
        if args.services: audits_to_run.append(("Running Services", RunningServicesAudit))
        if args.ports: audits_to_run.append(("Open Ports", OpenPortsAudit))
        if args.packages: audits_to_run.append(("Software Inventory", SW_Inventory))
        if args.users: audits_to_run.append(("Sudo/Users", SudoAudit))
    
    if not audits_to_run:
        print("No audits selected. Use --all or specify individual audits.")
        return
    
    # Run audits in parallel
    reports = {}
    with ThreadPoolExecutor() as executor:
        futures = []
        for name, audit_class in audits_to_run:
            futures.append(executor.submit(run_audit, audit_class))
        
        for (name, _), future in zip(audits_to_run, futures):
            reports[name] = future.result()
    
    # Generate and display summary
    print(generate_summary(reports))
    
    # Always save text output (default behavior)
    save_output(reports, args.output, "text")
    
    # Save additional formats if requested
    if args.json:
        save_output(reports, args.output, "json")
    if args.yaml:
        save_output(reports, args.output, "yaml")
    if args.csv:
        save_output(reports, args.output, "csv")

if __name__ == "__main__":
    main()