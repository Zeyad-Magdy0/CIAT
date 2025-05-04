import os
import stat
import argparse
import json
import yaml
import csv
from typing import List, Dict
from log import get_logger

logger = get_logger(__name__)

class FilePermissionsAudit:
    def __init__(self, output_file: str = None):
        self.output_file = output_file
        
    def is_world_writable(self, mode):
        return bool(mode & stat.S_IWOTH)
    
    def is_suid_or_sgid(self, mode):
        return bool(mode & (stat.S_ISUID | stat.S_ISGID))
    
    def check_critical(self) -> Dict[str, List[str]]:
        
        critical = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
        ]

        problems = {
            "world_writable": [],
            "wrong_ownership": [],
            "insecure_permissions": [],
        }
        
        for file in critical:
            if not os.path.exists(file):
                continue
            try:
                st = os.stat(file)
                if self.is_world_writable(st.st_mode):
                    problems["world_writable"].append(file)
                if self.is_suid_or_sgid(st.st_mode):
                    problems["insecure_permissions"].append(f"{file} is owned by UID: {st.st_uid}, GID: {st.st_gid}")
                if file == "/etc/shadow" and (st.st_mode & 0o077): # 0o077 is a bitmask that checks for rwx premissions for others
                    logger.warning(f"File {file} has insecure mode: {oct(st.st_mode)}")
                    problems["insecure_permissions"].append(f"{file} has mode {oct(st.st_mode)}")
            except PermissionError:
                logger.error(f"Failed to read {file}: Permission denied")
                
        return problems
    
    def find_world_writable_files(self, search: List[str]) -> List[str]:
        
        writable_files = []
        
        for base in search:
            for root, _, files in os.walk(base):
                for f in files:
                    path = os.path.join(root, f)  /shadow  
                    try:
                        if self.is_world_writable(os.stat(path).st_mode):
                            writable_files.append(path)
                    except Exception:
                        logger.error(f"Failed to read {path}")
        
        return writable_files
    
    def find_suid_sgid(self, search: List[str]) -> List[str]:
        
        suid_sgid_files = []
        
        for base in search:
            for root, _, files in os.walk(base):
                for f in files:
                    path = os.path.join(root, f)
                    try:
                        if self.is_suid_or_sgid(os.stat(path).st_mode):
                            suid_sgid_files.append(path)
                    except Exception:
                        logger.error(f"Failed to read {path}")
        
        return suid_sgid_files
    
    def audit(self, json_output=False, yaml_output=False, csv_output=False):
        
        report = {
                 "critical file issues": self.check_critical(),
                 "world writable files": self.find_world_writable_files(["/"]),
                 "suid or sgid files": self.find_suid_sgid(["/"])
                 }
        
        print("\n=== File Permissions Audit Report Start ===")
        
        # Dict[key: dict[str, List[str]] , key: list , key List ]
        
        for key, value in report.items():
            if value:
                print(f"{key} found:")
                
                if isinstance(value, dict):
                    for k, v in value.items():
                        print(f"{k}:")
                        
                        for _ in v:
                            print(f"  -{_}")
                else:
                    for _ in value:
                         print(f"  -{_}")
                            
        print("\n=== File Permissions Audit Report End ===")
        
        if json_output:
            print(json.dumps(report, indent=4))

        if yaml_output:
            print(yaml.dump(report, default_flow_style=False))

        if csv_output:
            
            output_file = self.output_file or "file_permissions_audit_output.csv"
            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Check", "Entries"])
                for key, values in report.items():
                    if isinstance(values, dict):
                        for subkey, sublist in values.items():
                            for val in sublist:
                                writer.writerow([f"{key}.{subkey}", val])
                    else:
                        for val in values:
                            writer.writerow([key, val])
            print(f"📄 CSV output written to {output_file}")
            
        if self.output_file and not csv_output:
            
            with open(self.output_file, "w") as f:
                for key, values in report.items():
                    f.write(f"{key}: \n")
                            
                    if isinstance(values, dict):
                        for subkey, subvals in values.items():
                            f.write(f"  {subkey}:\n")
                            for val in subvals:
                                f.write(f"    - {val}\n")
                    else:
                        for val in values:
                            f.write(f"  - {val}\n")
                            
        print(f"📄 Output written to {self.output_file}")
        

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Audit file permissions and ownership")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--yaml", action="store_true", help="Output in YAML format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--output", type=str, help="Write output to a file")

    args = parser.parse_args()

    audit = FilePermissionsAudit(output_file=args.output)
    audit.audit(json_output=args.json, yaml_output=args.yaml, csv_output=args.csv)