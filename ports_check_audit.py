import subprocess
import json, csv, yaml, argparse
from typing import List, Dict, Any
from log import get_logger

logger = get_logger(__name__)

class OpenPortsAudit:
    def __init__(self, output_file: str = None):
        self.output_file = output_file
        self.insecure_ports: List[int] = [
                                            21,    # FTP (cleartext credentials)
                                            22,    # SSH (only if using weak configurations)
                                            23,    # Telnet (cleartext everything)
                                            69,    # TFTP (no authentication)
                                            80,    # HTTP (cleartext traffic)
                                            161,   # SNMP (often insecure configurations)
                                            389,   # LDAP (cleartext by default)
                                            445,   # SMB (Windows file sharing - often exploited)
                                            1433,  # MS-SQL (often targeted)
                                            1521,  # Oracle DB
                                            3306,  # MySQL
                                            3389,  # RDP (Remote Desktop)
                                            5432,  # PostgreSQL
                                            5900,  # VNC (often weak auth)
                                            8080   # HTTP alternative (common in malware)
                                        ]


        self.sus_ports: List[int] = [
                                    4444,   # Metasploit default
                                    31337,  # Elite/Back Orifice
                                    1337,   # Leet speak common in malware
                                    6667,   # IRC (used by botnets)
                                    2745,   # Bagle worm
                                    12345,  # NetBus
                                    12346,  # NetBus
                                    20034,  # NetBus Pro
                                    27665,  # Trojan)
                                    54321,  # SchoolBus
                                    27374,  # Sub7
                                    65535,  # Attacks often use high ports
                                    # Add any organization-specific unusual ports
                                ]

    def check_open_ports(self) -> List[Dict[str,Any]]:
        try:
            result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
            lines = result.stdout.strip().split("\n")

            open_ports = []
            
            for line in lines[1:]:
                extract = line.split()
                if len(extract) >= 5:
                    protocol = extract[0]
                    port_number = extract[4].split(":")[-1]
                    if port_number.isdigit():
                        open_ports.append({"protocol": protocol, "port": int(port_number)})
            return open_ports
        except Exception as e:
            logger.error(f"Failed to check open ports: {e}")
            return []
        
    def check_insecure_ports(self, ports: List[Dict[str, Any]]) -> List[str]:
        
        return [f"{p['protocol'].upper()} port: {p['port']}" for p in ports if p['port'] in self.insecure_ports]
    
    def check_vul_ports(self, ports: List[Dict[str, Any]]) -> List[str]:
        return[f"{p['protocol'].upper()} port: {p['port']}" for p in ports if p['port'] in self.sus_ports]
    
    def audit(self, json_output = False, yaml_output = False, csv_output = False, output_file = None):
        
        ports = self.check_open_ports()
        insecure_ports = self.check_insecure_ports(ports)
        vul_ports = self.check_vul_ports(ports)
        
        report : Dict[str:Any] = {
            "Total Number of Open Ports": len(ports),
            "open ports": ports,
            "Insecure Ports": insecure_ports,
            "Vulnerable Ports": vul_ports,
        }
        
        print("\n=== Open Ports Audit Report Start ===")
        
        for key, value in report.items():
            print({f"{key}:"})
            
            if isinstance(value, list):
                for v in value:
                    print(f"  - {v}")
            else:
                print(f"  - {value}")
                
        print("\n=== Open Ports Audit Report End ===")
                
        if json_output:
            print("\n--- Open Ports Audit Report in JSON format ---")
            print(json.dumps(report, indent=4))
            print("\n--- Open Ports Audit Report in JSON format End---")

        if yaml_output:
            print("\n--- Open Ports Audit Report in YAML format ---")
            print(yaml.dump(report, default_flow_style=False))
            print("\n--- Open Ports Audit Report in YAML format End---")
            
        if csv_output:
            output = self.output_file or "open_ports_audit_output.csv"
            with open(output, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Type", "Details"])
                for key, val in report.items():
                    if isinstance(val, list):
                        for item in val:
                            writer.writerow([key, json.dumps(item)])
                    else:
                        writer.writerow([key, val])
            print(f"📄 CSV output written to {output}")

        if self.output_file and not csv_output:
            with open(self.output_file, "w") as f:
                for key, val in report.items():
                    f.write(f"{key}:")
                    if isinstance(val, list):
                        for item in val:
                            f.write(f"\n  - {item}")
                    else:
                        f.write(f" {val}\n")
            print(f"📄 Output written to {self.output_file}")
            
        print("\n=== Ports Check Audit Complete ===")
        
        
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Audit open ports and flag potentially insecure or suspicious ones.")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--yaml", action="store_true", help="Output in YAML format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--output", type=str, help="Write output to a file")

    args = parser.parse_args()
    audit = OpenPortsAudit(output_file=args.output)
    audit.audit(json_output=args.json, yaml_output=args.yaml, csv_output=args.csv)