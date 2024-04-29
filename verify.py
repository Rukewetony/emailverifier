import re
import dns.resolver
import subprocess
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def validate_email(email):
    # 1. Syntax Checking
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False, "Invalid email syntax"

    # Split email address into local part and domain
    local_part, domain = email.split('@')

    try:
        # 2. Domain Validation (DNS Lookup)
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)

        # Ping the mail server
        ping_result = subprocess.run(['ping', '-c', '1', mx_record], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ping_result.returncode != 0:
            return False, "Valid email address Failed MX verification"

        # 3. Disposable Email Detection
        with open('/home/sargin/Documents/Python/dispose.conf', 'r') as file:
            disposable_domains = [line.strip() for line in file.readlines()]
        if domain in disposable_domains:
            return False, "Disposable email address"

        # 4. Role Account Detection
        role_accounts = ["info", "support", "admin"] # Add more role accounts
        if local_part.lower() in role_accounts:
            return False, "Role account"

        # 5. TLD Validation
        with open('/home/sargin/Documents/Python/tld.json', 'r') as file:
            tld_whitelist = json.load(file)
        tld = domain.split('.')[-1]
        if tld not in tld_whitelist:
            return False, "Invalid TLD"

        # 6. Catch-All Email Validation (Query Mail Server Configuration)
        catch_all_result = query_mail_server(domain)
        if catch_all_result:
            return False, "Catch-all email policy detected (Server config)"

        # 7. Catch-All Email Validation (DNS Lookup)
        catch_all_result = dns_lookup(domain)
        if catch_all_result:
            return False, "Catch-all email policy detected (DNS lookup)"

        # All checks passed, email is valid
        return True, "Valid email address"
    except Exception as e:
        return False, str(e)

def query_mail_server(domain):
    try:
        # Connect to the mail server
        with smtplib.SMTP(domain) as server:
            # Send EHLO command to get server configuration
            server.ehlo()
            # Check if the server supports a catch-all address
            if "250-8BITMIME" in server.esmtp_features:
                return True
            else:
                return False
    except Exception as e:
        print("Error querying mail server:", e)
        return False

def dns_lookup(domain):
    # Placeholder function for performing DNS lookup
    # Modify this function to perform the actual DNS lookup
    # Example: return True if catch-all policy detected, False otherwise
    return False

# Test the function
email = input("Enter an email address to validate: ")
is_valid, reason = validate_email(email)
print("Validation result:", reason)
