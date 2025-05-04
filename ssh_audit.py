import os
import yaml
import json
import argparse
import csv
from typing import Dict
from log import get_logger

logger = get_logger(__name__)


class SSHAudit:
    def __init__(self, config_file: str = "/etc/ssh/sshd_config", output_file: str = None):
        self.config_file = config_file
        self.output_file = output_file

    def parse_ssh(self, config_file: str) -> Dict[str, str]:
        
        if not os.path.exists(config_file):
            logger.error(f"Configuration file {config_file} does not exist.")
            raise FileNotFoundError(f"SSH config file not found: {config_file}")

        results = {}
        with open(config_file, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                key, *value = line.split()
                results[key] = " ".join(value)
        return results

    def run(self, config: Dict[str, str]) -> Dict[str, str]:
        
        report = {}

        if config.get("PermitRootLogin", "yes") == "yes":
            report["PermitRootLogin"] = "[!] Root login is allowed — bad practice"
            logger.warning("Root login enabled")

        if config.get("PasswordAuthentication", "yes") == "yes":
            report["PasswordAuthentication"] = "[!] Password authentication is allowed — bad practice"
            logger.warning("Password Authentication is enabled")

        if config.get("PermitEmptyPasswords", "no") == "yes":
            report["PermitEmptyPasswords"] = "[!] Empty passwords are allowed — bad practice"
            logger.warning("Empty Passwords are allowed")

        if config.get("Protocol", "2") != "2":
            report["Protocol"] = "[!] SSH protocol is not version 2 — bad practice"
            logger.warning("Non-v2 SSH protocol used")

        if config.get("X11Forwarding", "no") == "yes":
            report["X11Forwarding"] = "[!] X11 forwarding is allowed — bad practice"
            logger.warning("X11 Forwarding is allowed")

        if "MaxAuthTries" in config and int(config["MaxAuthTries"]) > 5:
            report["MaxAuthTries"] = "[!] Too many auth attempts allowed — bad practice"
            logger.warning("More than 5 auth attempts allowed")

        if config.get("PermitUserEnvironment", "no") == "yes":
            report["PermitUserEnvironment"] = "[!] User environment variables are allowed — bad practice"
            logger.warning("PermitUserEnvironment is enabled")

        if "Ciphers" in config:
            weak = ["aes128-cbc", "3des-cbc", "arcfour", "blowfish-cbc", "rc4", "md5"]
            if any(c in config["Ciphers"] for c in weak):
                report["Ciphers"] = f"[!] Weak ciphers enabled: {config['Ciphers']}"
                logger.warning("Weak ciphers found")

        if "LoginGracetime" in config:
            try:
                seconds = int(config["LoginGracetime"].strip("s"))
                if seconds > 60:
                    report["LoginGracetime"] = f"[!] Login grace time too long: {config['LoginGracetime']}"
                    logger.warning("Login grace time too long")
            except ValueError:
                pass

        if config.get("Port") == "22" or "Port" not in config:
            report["Port"] = "[!] Default SSH port 22 used — consider changing"
            logger.warning("Default SSH port in use")
        else:
            report["Port"] = f"[+] Custom SSH port used: {config['Port']}"

        for key in ["AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups"]:
            if key in config:
                report[key] = f"[+] {key} = {config[key]}"
                logger.info(f"{key} configured")

        if not any(k in config for k in ["AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups"]):
            report["AccessControl"] = "[!] No access control (Allow/Deny Users/Groups) defined"
            logger.warning("No Allow/Deny access control found")

        return report

    def audit(self, json_output=False, yaml_output=False,
              score=False, csv_output=False):
        
        config = self.parse_ssh(self.config_file)
        report = self.run(config)

        print("\n=== SSH Configuration Audit Report Start===")
        print("--- Cechking for bad practices in the SSH configuration ---")
        
        print("\n--- SSH Configuration Audit Textual Report ---")
        for key, msg in report.items():
            print(f"{key}: {msg}")
            
        if score:
            bad_count = sum(1 for msg in report.values() if "[!]" in msg)
            print(f"❌ Vulnerabilities found: {bad_count}")

        if json_output:
            print("\n--- SSH Configuration Audit Report in JSON format ---")
            output = json.dumps(report, indent=4)
            print(output)

        if yaml_output:
            print("\n--- SSH Configuration Audit Report in YAML format ---")
            output = yaml.dump(report, default_flow_style=False)
            print(output)

        if csv_output:
            csv_file = self.output_file or "ssh_audit_output.csv"
            with open(csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Setting", "Assessment"])
                for key, msg in report.items():
                    writer.writerow([key, msg])
            print(f"CSV output written to {csv_file}")
   
        if self.output_file and not csv_output:
            with open(self.output_file, "w") as f:
                f.write("\n".join([f"{k}: {v}" for k, v in report.items()]))
            print(f"📄 Output written to {self.output_file}")

        print("\n=== SSH Configuration Audit Report End===")
        

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="SSH Configuration Audit Tool")
    parser.add_argument(
        "-c", "--config", default="/etc/ssh/sshd_config",
        help="Path to sshd_config file"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file to save the audit results"
    )
    
    parser.add_argument(
        "--json", action="store_true",
        help="Output in JSON format"
    )
    parser.add_argument(
        "--yaml", action="store_true",
        help="Output in YAML format"
    )
    parser.add_argument(
        "--csv", action="store_true",
        help="Output in CSV format"
    )
    parser.add_argument(
        "--score", action="store_true",
        help="Show number of bad practices found"
    )
    parser.add_argument(
        "--text", action="store_true",
        help="Print text-based report"
    )

    args = parser.parse_args()

    audit = SSHAudit(config_file=args.config, output_file=args.output)
    audit.audit(
        json_output=args.json,
        yaml_output=args.yaml,
        csv_output=args.csv,
        score=args.score,
    )