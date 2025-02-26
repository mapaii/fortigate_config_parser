import re
import json
import os

def load_config(file_path):
    """Load FortiGate configuration file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    with open(file_path, 'r') as file:
        return file.readlines()

def check_cis_compliance(config_lines):
    """Check configuration against CIS Benchmark rules."""
    findings = []

    #Rule: Ensure DNS server is configured
    if not any(re.search(r'set\s+primary', line) for line in config_lines) and not any(re.search(r'primary:', line) for line in config_lines): 
        findings.append("DNS Server not configured.")

    if not any(re.search(r'set\s+secondary', line) for line in config_lines) and not any(re.search(r'secondary:', line) for line in config_lines): 
        findings.append("Secondary DNS Server not configured.")


    #Rule: Disable all management related services on WAN port
    if any(re.search(r'set allowaccess ping https ssh', line) for line in config_lines):
        findings.append("HTTPS SSH access allowed on Interface make sure this is not WAN port.")

    #Rule: Ensure 'Pre-Post-Login Banner' is set
    if not any(re.search(r'set pre-login-banner enable', line) for line in config_lines) and not any(re.search(r'post-login-banner: enable', line) for line in config_lines): 
        findings.append("Pre-Login Banner not configured.")
    if not any(re.search(r'set post-login-banner enable', line) for line in config_lines)and not any(re.search(r'pre-login-banner: enable', line) for line in config_lines): 
        findings.append("Post-Login Banner not configured.")
    

    # Rule: Ensure strong password policy
    if not any(re.search(r'set status enable', line) for line in config_lines) and not any(re.search(r'set expire-day', line) for line in config_lines) and not any(re.search(r'set min-lower-case-letter', line) for line in config_lines) and not any(re.search(r'set min-upper-case-letter', line) for line in config_lines) and not any(re.search(r'set min-non-alphanumeric', line) for line in config_lines) and not any(re.search(r'set reuse-password disable', line) for line in config_lines) and not any(re.search(r'status: enable', line) for line in config_lines) and not any(re.search(r'min-lower-case-letter:', line) for line in config_lines) and not any(re.search(r'min-upper-case-letter:', line) for line in config_lines) and not any(re.search(r'min-non-alphanumeric:', line) for line in config_lines) and not any(re.search(r'expire-status: enable', line) for line in config_lines):
        findings.append("Password policy enforcement is disabled.")
    
    # Rule : Ensure administrator password retries and lockout time are configured
    if not any(re.search(r'auth-lockout-duration', line) for line in config_lines): 
        findings.append("Administrator password retries and lockout time are not configured.")
    
    # Rule : Ensure logging is enabled
    if not any(re.search(r'set logtraffic all', line) for line in config_lines):
        findings.append("Logging is not set to capture all traffic.")
    
    # Rule : Ensure Admin access is secured
    if not any(re.search(r'set admin-telnet disable', line) for line in config_lines) and not any(re.search(r'admin-telnet: disable', line) for line in config_lines):
        findings.append("Telnet Should be disabled globally.")
    if any(re.search(r'set admin-ssh-port 22', line) for line in config_lines):
        findings.append("Recommend not to use default SSH Port 22.")
    if any(re.search(r'set admin-sport 443', line) for line in config_lines):
        findings.append("Default Admin Port 443 Used.")
    if not any(re.search(r'set trusthost1', line) for line in config_lines):
        findings.append("login accounts is not having specific trusted hosts enabled.")
    if not any(re.search(r'set admintimeout', line) for line in config_lines) and not any(re.search(r'admintimeout:', line) for line in config_lines):
        findings.append("lidle timeout time is not configured")
    

    # Rule : Ensure TLS 1.2+ is enabled
    if not any(re.search(r'set ssl-min-proto-version TLSv1-2', line) for line in config_lines):
        findings.append("TLS 1.2+ is not enforced.")
    
    # Rule : Ensure SNMP is not using default community strings
    if any(re.search(r'set community public', line) for line in config_lines):
        findings.append("SNMP is using the default 'public' community string.")
    # Rule : Ensure only SNMPv3 is enabled
    if not any(re.search(r'set security-level auth-priv', line) for line in config_lines) and not any(re.search(r'set auth-proto sha256', line) for line in config_lines) or not any(re.search(r'sset priv-proto aes256', line) for line in config_lines):
        findings.append("SNMPv3 is not enabled.")
    
    # Rule : Ensure administrative access via HTTP is disabled
    if any(re.search(r'set admin-http enable', line) for line in config_lines):
        findings.append("Administrative access via HTTP is enabled instead of HTTPS.")
    
    # Rule : Ensure strong firewall policies are enforced
    if any(re.search(r'set action accept', line) for line in config_lines) and \
       not any(re.search(r'set schedule always', line) for line in config_lines):
        findings.append("Firewall rules allow traffic without strict scheduling.")
    if any(re.search(r'set service "ALL"', line) for line in config_lines):
        findings.append("Policies with 'ALL' as Service Present, please check.")
    
    # Rule : Ensure system time is synchronized (NTP enabled)
    if not any(re.search(r'set ntpsync enable', line) for line in config_lines):
        findings.append("NTP server is not configured, which may cause time synchronization issues.")
    
    # Rule : Ensure botnet detection is enabled
    if not any(re.search(r'set ips-sensor "default"', line) for line in config_lines):
        findings.append("IPS default Policy enabled.")
    
    # Rule : Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB
    if not any(re.search(r'edit "Tor-', line) for line in config_lines) :
        findings.append("Tfirewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB not configured")

    # Rule : Ensure antivirus settings are enabled
    if not any(re.search(r'set av-profile', line) for line in config_lines):
        findings.append("Ensure Antivirus Profile enabled for all Policies.")
    if not any(re.search(r'set grayware enable', line) for line in config_lines):
        findings.append("Antivirus grayware detection not enabled.")
    
    if not any(re.search(r'set av-outbreak-prevention enable', line) for line in config_lines):
        findings.append("Outbreak Prevention Database is not enabled.")
    
    if not any(re.search(r'set machine-learning-detection enable', line) for line in config_lines):
        findings.append("AI/Heuristic-based malware detection is not enabled.")
    
    if not any(re.search(r'set av-grayware enable', line) for line in config_lines):
        findings.append("Grayware detection is not enabled in antivirus settings.")

    if not any(re.search(r'set action-type quarantine', line) for line in config_lines):
        findings.append("Compromised Host Quarantine is not enabled.")
    
    
    # Rule 12: Ensure Security Fabric is enabled
   # if not any(re.search(r'set security-fabric enable', line) for line in config_lines):
   #     findings.append("Security Fabric is not configured.")

    #General Guideline 
    if any(re.search(r'Fortigate', line, re.IGNORECASE) for line in config_lines):
        findings.append("")  # Add a blank line
        findings.append("")  # Add another blank line
        findings.append("### Fortigate General Guideline - Best Practices.")
        findings.extend([
        "Ensure the latest firmware is installed.",
        "Disable USB Firmware and configuration installation - set auto-install-config disable set auto-install-image disable.",
        "Ensure timezone is properly configured.",
        "Ensure hostname is set - set hostname New_FGT1.",
        "Disable static keys for TLS - set ssl-static-key-ciphers disable.",
        "Enable Global Strong Encryption - set strong-crypto enable.",
        "Disable all management-related services on WAN port.",
        "Ensure management GUI listens on secure TLS version - set admin-https-ssl-versions tlsv1-3.",
        "Ensure administrator password retries and lockout time are configured - set admin-lockout-threshold 3 set admin-lockout-duration 60.",
        "Ensure only SNMPv3 is enabled & Allow only trusted hosts in SNMPv3.",
        "Ensure that unused policies are reviewed regularly - diag firewall iprope show 100004 <policy-id>.",
        "Ensure logging is enabled on all firewall policies.",
        "Ensure relevant IPS Profile enabled to Detect Botnet connections.",
        "Ensure Antivirus Definition Push Updates are Configured."
    ])

       # findings.append("Ensure management GUI listens on secure TLS version-set admin-https-ssl-versions tlsv1-3.")
    
    
    return findings

def generate_report(findings, output_file):
    """Generate a report with non-compliance issues."""
    with open(output_file, 'w') as file:
        json.dump({"Non Compliance Issue": findings}, file, indent=4)
    print(f"Report saved to {output_file}")

if __name__ == "__main__":
    config_backup_folder = "Config_Backup"
    report_folder = "Report"
    
    os.makedirs(config_backup_folder, exist_ok=True)
    os.makedirs(report_folder, exist_ok=True)
    
    for config_file in os.listdir(config_backup_folder):
        config_path = os.path.join(config_backup_folder, config_file)
        report_path = os.path.join(report_folder, f"{os.path.splitext(config_file)[0]}_report.txt")
        
        try:
            config_data = load_config(config_path)
            anomalies = check_cis_compliance(config_data)
            generate_report(anomalies, report_path)
        except FileNotFoundError as e:
            print(e)
