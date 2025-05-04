import subprocess
import platform
import json, yaml, csv, argparse
from typing import List,Dict,Any
from log import get_logger

logger = get_logger(__name__)

class RunningServicesAudit:
    def __init__(self, output_file=None):
        self.output_file = output_file
        self.system = platform.system().lower()
        self.sus_keywords : List[str] = [
                                            # Remote Access/Backdoors
                                            "telnet", "backdoor", "shell", "reverse_shell", "bind_shell", 
                                            "meterpreter", "c99", "r57", "webadmin", "mini_httpd",

                                            # File Transfer
                                            "vsftpd", "proftpd", "pure-ftpd", "ftp", "tftp", "wget", "curl",

                                            # Network Tools
                                            "nc", "netcat", "socat", "ncat", "hping", "tcpdump", "wireshark",

                                            # Web Shells/Exploits
                                            "cgi-bin", "miniserv", "webadmin", "phpbackdoor", "r57shell",
                                            "c99shell", "b374k", "weevely",

                                            # Database
                                            "mysql", "postgres", "mongod", "redis", "memcached",

                                            # Remote Management
                                            "vnc", "x11vnc", "tightvnc", "teamviewer", "anydesk", "ammyy",

                                            # Malware Related
                                            "cryptominer", "minerd", "xmrig", "ccminer", "locker", "ransom",
                                            "crypt", "encrypt", "decrypt",

                                            # Suspicious Services
                                            "irc", "eggdrop", "bnc", "socks", "proxy", "tor", "i2p",

                                            # Exploitation Frameworks
                                            "metasploit", "armitage", "cobaltstrike", "empire", "powersploit",

                                            # Privilege Escalation
                                            "sudoers", "suid", "passwd", "shadow", "cron", "atd",

                                            # Obfuscation
                                            "base64", "xxd", "gzip", "bzip2", "openssl_enc",

                                            # Your existing entries
                                            "rsh", "telnet", "vsftpd", "miniserv", "nc", "backdoor", "ftp"
                                        ]
                                        
    def check_running_services(self) -> List[str]:
        
        try:
            result = subprocess.run (["systemctl", "list-units", "--type=service", "--state=running"], capture_output=True, text=True)
            lines = result.stdout.strip().split("\n")
            services = [line.split()[0] for line in lines if ".service" in line]
            return services
        except Exception as e:
            logger.warning(f"Failed to check running services: {e}")
            
            try:
                result = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True, check=True)
                return result.stdout.strip().split('\n')[1:]
            except Exception as e:
                logger.error(f"Failed to check running services: {e}")
                return []
    
    def find_sus_services(self, services: List[str]) -> List[str]:
        
        sus: List[str] = []
        for service in services:
            for keyword in self.sus_keywords:
                if keyword.lower() in service.lower():
                    sus.append(service)
        return sus
    
    def audit(self, json_output = False, yaml_output = False, csv_output = False, output_file = None):
        
        services = self.check_running_services()
        sus = self.find_sus_services(services)
        
        report : Dict[str,Any] = {
            "Operating System": self.system,
            "Total Running Services": len(services),
            "Running Services": services,
            "Suspicious Services": sus,
        }
        
        print("\n=== Running Services Audit Report Start ===")
        
        for key, value in report.items():
            print({f"{key}:"})
            
            if isinstance(value, list):
                for v in value:
                    print(f"  - {v}")
            else:
                print(f"  - {value}")
                
        print("\n=== Running Services Audit Report End ===")
        
        if json_output:
            print("\n--- Running Services Audit Report in JSON format ---")
            print(json.dumps(report, indent=4))
            print("\n--- Running Services Audit Report in JSON format End---")

        if yaml_output:
            print("\n--- Running Services Audit Report in YAML format ---")
            print(yaml.dump(report, default_flow_style=False))
            print("\n--- Running Services Audit Report in YAML format End---")
            
        if csv_output:
            output = self.output_file or "running_services_audit_output.csv"
            with open(output, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Service", "Status"])
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
            
        print("\n=== Services Audit Complete ===")


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Audit open ports and flag potentially insecure or suspicious ones.")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--yaml", action="store_true", help="Output in YAML format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--output", type=str, help="Write output to a file")

    args = parser.parse_args()
    audit = RunningServicesAudit(output_file=args.output)
    audit.audit(json_output=args.json, yaml_output=args.yaml, csv_output=args.csv)