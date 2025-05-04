import json, csv, yaml, argparse
import subprocess,platform
from typing import List,Dict,Optional
from log import get_logger

logger = get_logger(__name__)

class FirewallRulesAudit:
    def __init__(self, output_file=None, safe_ports: Optional[List[int]] = None):
        self.output_file = output_file
        self.firewall_tool = self.detect_firewall_tool()
        self.safe_ports = safe_ports or [22, 80, 443] # default safe ports
        self.default_rule_signatures = [
            "ufw allow ssh",
            "ACCEPT     all  --  anywhere             anywhere"
        ]

        
        
    def detect_firewall_tool(self) -> str:
        

        if platform.system().lower() != "linux":
            logger.warning("Firewall rules audit is only supported on Linux")
            return ""
        
        try:
            
            if subprocess.run("command -v ufw", shell=True, capture_output=True).returncode == 0:
                ufw_status = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True)
                if "Status: active" in ufw_status.stdout:
                    return "ufw"
                
            if subprocess.run("command -v firewall-cmd", shell=True, capture_output=True).returncode == 0:
                firewalld_state = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True)
                if "running" in firewalld_state.stdout:
                    return "firewalld"
            
            if subprocess.run("command -v iptables", shell=True, capture_output=True).returncode == 0:
                return "iptables"
        
        except Exception as e:
            logger.error(f"Failed to detect firewall tool: {e}")
            return ""
            
           
    
    def list_firewall_rules(self) -> List[str]:
        
        result =[]
        
        try:
            if self.firewall_tool == "ufw":
                result = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True)
                rules = result.stdout.strip().split("\n")
            elif self.firewall_tool == "firewalld":
                result = subprocess.run(["firewall-cmd", "--list-all"], capture_output=True, text=True)
                rules = result.stdout.strip().split("\n")
            elif self.firewall_tool == "iptables":
                result = subprocess.run(["sudo", "iptables", "-L"], capture_output=True, text=True)
                rules = result.stdout.strip().split("\n")
            else:
                logger.error("Unsupported firewall tool")
                
        except PermissionError as e:
            logger.error(f"Failed to list firewall rules: {e}")
            
        return rules
    
    def check_default_firewall_rules(self, rules: List[str]) -> List[str]:
        
        defaults = []
        
        for rule in rules:
            for sig in self.default_rule_signatures:
                if sig in rule:
                    defaults.append(rule)
        
        return defaults
    
    def check_for_unsafe_ports(self, rules: List[str]) -> List[str]:
        
        unnecessary = []
        
        for rule in rules:
            if "ACCEPT" in rule and any(protoctol in rule for protoctol in ["tcp", "udp"]):
                if not any(str(p) in rule for p in self.safe_ports):
                    unnecessary.append(rule)
                            
        return unnecessary
    
    def audit(self, json_output=False, yaml_output=False, csv_output=False):
        
        rules = self.list_firewall_rules()
        defaults = self.check_default_firewall_rules(rules)
        unnecessary = self.check_for_unsafe_ports(rules)
        firewall_tool = self.firewall_tool
        
        report = {
            "Operating System": platform.system(),
            "Firewall Tool": firewall_tool,
            "Total Number of Firewall Rules": len(rules),
            "Firewall Rules": rules,
            "Default Firewall Rules": defaults,
            "Unnecessary Firewall Rules": unnecessary
        }
        
        print("\n=== Firewall Rules Audit Report Start ===")
        
        for key, value in report.items():
            print(f"{key}:")
            
            if isinstance(value, list):
                for v in value:
                    print(f"  - {v}")
            else:
                print(f"  - {value}")
                
        if json_output:
            print("\n--- Running Services Audit Report in JSON format ---")
            print(json.dumps(report, indent=4))
            print("\n--- Running Services Audit Report in JSON format End---")

        if yaml_output:
            print("\n--- Running Services Audit Report in YAML format ---")
            print(yaml.dump(report, default_flow_style=False))
            print("\n--- Running Services Audit Report in YAML format End---")
            
        if csv_output:
            output_file = self.output_file or "firewall_rules_audit_output.csv"
            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Check", "Entries"])
                for key, values in report.items():
                    if isinstance(values, list):
                        for val in values:
                            writer.writerow([key, val])
                    else:
                        writer.writerow([key, values])
            print(f"📄 CSV output written to {output_file}")

        if self.output_file and not csv_output:
            with open(self.output_file, "w") as f:
                for key, values in report.items():
                    f.write(f"{key}:\n")
                    if isinstance(values, list):
                        for val in values:
                            f.write(f"  - {val}\n")
                    else:
                        f.write(f"  {values}\n")
            print(f"📄 Output written to {self.output_file}")

        print("\n=== Firewall Rules Audit Report End ===")
        
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Audit firewall rules and configuration")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--yaml", action="store_true", help="Output in YAML format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--output", type=str, help="Write output to a file")
    parser.add_argument("--safe-ports", type=int, nargs="+", help="List of allowed ports (space-separated)")

    args = parser.parse_args()

    audit = FirewallRulesAudit(output_file=args.output, safe_ports=args.safe_ports)
    audit.audit(json_output=args.json, yaml_output=args.yaml, csv_output=args.csv)