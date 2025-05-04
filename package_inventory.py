import subprocess
import platform
import json
import yaml
import csv
import argparse
from typing import List, Dict, Any
from log import get_logger


logger = get_logger(__name__)


class SW_Inventory():
    def __init__(self, output_file: str = None):
        
        self.output_file = output_file
        self.system = platform.system().lower()
        self.distro = self.get_linux_distro() if self.system == 'linux' else None
        self.suspicous_keywords = ["netcat", "nmap", "john", "hydra", "aircrack", "sqlmap", "wireshark"]
        self.vul_software = ["openssl < 1.1.1", "bash < 4.4", "sudo < 1.8.28"] 
        self.deprecated_packages = [
                                    "distutils",
                                    "asyncore",
                                    "asynchat",
                                    "imp",
                                    "optparse",
                                    "cgi",
                                    "platform.linux_distribution()",
                                    "MySQLdb",
                                    "futures",
                                    "mock",
                                    "pathlib2",
                                    "enum34",
                                    "urllib2",
                                    "ConfigParser",
                                    "thread",
                                    "collections.MutableMapping",
                                    "collections.MutableSequence"
                                ]
    
    def get_linux_distro(self) -> str:

        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("ID="):
                        return line.split("=")[1].strip().strip('"')
        except FileNotFoundError:
            logger.error("Failed to read /etc/os-release: File not found")
            return None
            
    def get_installed_software(self) -> List[str]:
        
        if not self.distro:
            logger.warning("Cannot detect Linux distribution")
            return []
        
        try:
            if "debian" in self.distro or "ubuntu" in self.distro:
                result = subprocess.run(["dpkg", "-l"], capture_output=True, text=True)
            elif "centos" in self.distro or "redhat" in self.distro or "fedora" in self.distro:
                result = subprocess.run(["rpm", "-qa"], capture_output=True, text=True)
            else:
                logger.warning("This linux distribution is not supported")
                return []
        
            return result.stdout.strip().split("\n")
        
        except Exception as e:
            logger.error(f"Failed to get installed software: {e}")
            return []  

    def find_sus_software(self, packages: List[str]) -> List[str]:
        
        sus: List[str] = []
        for package in packages:
            for keyword in self.suspicous_keywords:
                if keyword.lower() in package.lower():
                    sus.append(package)
        return sus
    
    def check_vul_software(self, packages: List[str]) -> List[str]:
        vul: List[str] = []
        for package in packages:
            for keyword in self.vul_software:
                if keyword.lower() in package.lower():
                    vul.append(package)
        return vul
    
    def check_deprecated_software(self, packages: List[str]) -> List[str]:
        deprecated: List[str] = []
        for package in packages:
            for keyword in self.deprecated_packages:
                if keyword.lower() in package.lower():
                    deprecated.append(package)
        return deprecated
    
    def audit(self, json_output=False, yaml_output=False, csv_output=False, output_file=None):
        
        packages = self.get_installed_software()
        sus = self.find_sus_software(packages)
        vul = self.check_vul_software(packages)
        deprecated = self.check_deprecated_software(packages)
        
        report: Dict[str, Any] = {
            "Operating System": self.system,
            "Distribution": self.distro,
            "Total Packages": len(packages),
            "Suspicious Packages": sus,
            "Vulnerable Packages": vul,
            "Deprecated Software": deprecated,
        }
        
        print("\n=== Software Inventory Audit Report Start ===")
        
        for key, value in report.items():
            print({f"{key}:"})
        
            if isinstance(value, list):
                for v in value:
                    print(f"  - {v}")
            else:
                print(f"  - {value}")
                
        print("\n=== Package Inventory Audit Report End ===")
        
        if json_output:
            print("\n--- Package Inventory Audit Report in JSON format ---")
            output = json.dumps(report, indent=4)
            print(output)
            
        if yaml_output:
            print("\n--- Package Inventory Audit Report in YAML format ---")
            output = yaml.dump(report, default_flow_style=False)
            print(output)
            
        if csv_output:
            output_file = self.output_file or "package_inventory_output.csv"
            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Check", "Entries"])
                for key, items in report.items():
                    writer.writerow([key, "; ".join(items)])
            print(f"📄 CSV output written to {output_file}")
            
        if self.output_file and not csv_output:
            with open(self.output_file, "w") as f:
                for key, value in report.items():
                    f.write({f"{key}:"})
        
                    if isinstance(value, list):
                        for v in value:
                            f.write(f"  - {v}")
                    else:
                        f.write(f"  - {value}")

                        
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Audit installed software packages for security issues")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--yaml", action="store_true", help="Output results in YAML format")
    parser.add_argument("--csv", action="store_true", help="Output results in CSV format")
    parser.add_argument("--output", type=str, help="Output file path for CSV")
    args = parser.parse_args()

    audit = SW_Inventory()
    audit.audit(json_output=args.json, yaml_output=args.yaml,
                csv_output=args.csv, output_file=args.output)