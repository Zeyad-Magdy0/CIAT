import os
import re
import json
import yaml
import argparse
import csv
from typing import List, Dict

from log import get_logger

logger = get_logger("__name__")


class SudoAudit:
    def __init__(self, sudo_file: str = "/etc/sudoers",
                 sudoers_d_dir: str = "/etc/sudoers.d",
                 passwd_file: str = "/etc/passwd",
                 shadow_file: str = "/etc/shadow", 
                 output_file: str = None):
         
        self.sudo_file = sudo_file
        self.sudoers_d_dir = sudoers_d_dir
        self.passwd_file = passwd_file
        self.shadow_file = shadow_file
        self.output_file = output_file
        
    def read_sudo_files(self):
        result = []
        
        if os.path.exists(self.sudo_file):
            try:
                with open(self.sudo_file, "r") as f:
                    result.extend(f.readlines())
            except PermissionError:
                logger.error(f"Failed to read {self.sudo_file}: Permission denied")

        if os.path.isdir(self.sudoers_d_dir):
            for filename in os.listdir(self.sudoers_d_dir):
                full_path = os.path.join(self.sudoers_d_dir, filename)
                if os.path.isfile(full_path):
                    try:
                        with open(full_path, "r") as f:
                            result.extend(f.readlines())
                    except PermissionError:
                        logger.error(f"Failed to read {full_path}: Permission denied")

        return result
    
    def check_user_acc(self) -> Dict[str, List[str]]:
        
        report = {
            "empty_passwords": [],
            "locked_accounts": [],
            "no_password_set": [],
            "system_users_with_shells": [], 
        }
        
        shadow_data = {}
        
        try:
            with open(self.shadow_file, "r") as f:
                for line in f:
                    extract = line.strip().split(":")
                    if len(extract) > 1:
                        shadow_data[extract[0]] = extract[1]
        except PermissionError:
            logger.error("Failed to read /etc/shadow: Permission denied")
        
        try:
            with open(self.passwd_file, "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) < 7:
                        continue
                    username, _, uid, _, _, _, shell = parts
                    uid = int(uid)
                    if username not in shadow_data:
                        continue
                    hash = shadow_data.get(username, "")
                    
                    if hash == "":
                        report["empty_passwords"].append(username)
                    elif hash == "!!":
                        report["no_password_set"].append(username)
                    elif hash.startswith("!") or hash.startswith("*"):
                        report["locked_accounts"].append(username)
                        
                    if uid < 1000 and shell in ["/bin/bash", "/bin/sh", "/bin/zsh"]:
                        report["system_users_with_shells"].append(f"{username}, UID: {uid}, Shell: {shell}")
                        
        except PermissionError:
            logger.error("Failed to read /etc/passwd: Permission denied")  
            
        return report
                             
    def check_conf(self, reader: List[str]) -> Dict[str, List[str]]:
        
        report = { 
                  "NOPASSWD": [],
                  "wildcards": [],
                  "included_files": []
                }
        
        for line in reader:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            
            if "NOPASSWD" in line:
                report["NOPASSWD"].append(line)
            
            if re.search(r"\bALL\s*=\s*\(ALL\)\s*ALL", line, re.IGNORECASE):
                report["wildcards"].append(line)
            
            if line.startswith("include") or line.startswith("includedir"):
                report["included_files"].append(line)          
            
        return report
    
    def audit(self, json_output=False, yaml_output=False, csv_output=False, output_file=None):
        
        lines = self.read_sudo_files()
        sudo_report = self.check_conf(lines)
        user_report = self.check_user_acc()
        full_report = {**sudo_report, **user_report}
        
        print("\n=== Sudo Configuration Audit Report Start===")
        
        for key, value in sudo_report.items():
            if value:
                print(f"{key} entries found:")
                for _ in value:
                    print(f"{_}")
            else:
                print(f"\n✅ No suspicious {key} entries found.")       
                     
        print("\n=== Sudo Configuration Audit Report End ===")
        
        print("\n=== User Account Audit Report Start===")
        
        for key, users in user_report.items():
            if users:
                print(f"{key.replace('_', ' ').capitalize()}:")
                for user in users:
                    print(f"{user}")
            else:
                print(f"\n No {key.replace('_', ' ').capitalize()} found.")
        
        print("\n=== User Account Audit Report End ===")
        
        if json_output:
            print("\n--- Sudo Configuration Audit Report in JSON format ---")
            print(json.dumps(full_report, indent=4))

        if yaml_output:
            print("\n--- Sudo Configuration Audit Report in YAML format ---")
            print(yaml.dump(full_report, default_flow_style=False))
        
        if csv_output:
            output_file = self.output_file or "sudo_audit_output.csv"
            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Check", "Entries"])
                for key, items in full_report.items():
                    writer.writerow([key, "; ".join(items)])
            print(f"📄 CSV output written to {output_file}")
            
        if self.output_file and not csv_output:
            with open(self.output_file, "w") as f:
                for key, values in full_report.items():
                    f.write(f"{key}:\n")
                    if not values:
                        f.write(f"None value found for {key}\n")
                else:
                    for val in values:
                        f.write(f"  - {val}\n")
            print(f"📄 Output written to {self.output_file}")
            
        print("\n=== Audit Complete ===")
        

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Audit sudo configurations and user accounts")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--yaml", action="store_true", help="Output in YAML format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--output", type=str, help="Write output to a file")

    args = parser.parse_args()

    audit = SudoAudit(output_file=args.output)
    audit.audit(json_output=args.json, yaml_output=args.yaml, csv_output=args.csv)

