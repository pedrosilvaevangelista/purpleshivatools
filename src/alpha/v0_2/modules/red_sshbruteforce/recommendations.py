recommendations = [
    {
        "id": 1,
        "title": "Use Strong, Unique Passwords",
        "severity": "High",
        "description": "Avoid weak or common passwords to prevent brute force attacks.",
        "specificDetails": {
            "recommendation": "Enforce password policies requiring minimum length, complexity, and regular changes."
        },
        "sources": [
            "NIST Digital Identity Guidelines",
            "OWASP Authentication Cheat Sheet"
        ]
    },
    {
        "id": 2,
        "title": "Enable Two-Factor Authentication (2FA)",
        "severity": "High",
        "description": "Adds an additional security layer beyond just a password.",
        "specificDetails": {
            "recommendation": "Use 2FA tools such as Google Authenticator or hardware tokens."
        },
        "sources": [
            "NIST 800-63B",
            "OWASP Two-Factor Authentication Guide"
        ]
    },
    {
        "id": 3,
        "title": "Limit SSH Access by IP Address",
        "severity": "Medium",
        "description": "Restrict SSH access to trusted IP ranges to reduce attack surface.",
        "specificDetails": {
            "recommendation": "Configure firewall rules or use SSH daemon settings to restrict access."
        },
        "sources": [
            "Linux SSH Hardening Guide",
            "Cisco Firewall Configuration Best Practices"
        ]
    },
    {
        "id": 4,
        "title": "Use Fail2Ban or Similar Intrusion Prevention Tools",
        "severity": "Medium",
        "description": "Automatically block IPs that show suspicious SSH login failures.",
        "specificDetails": {
            "recommendation": "Install and configure Fail2Ban to monitor SSH logs and block attackers."
        },
        "sources": [
            "Fail2Ban Official Documentation",
            "Linux Security Best Practices"
        ]
    },
    {
        "id": 5,
        "title": "Disable Root Login Over SSH",
        "severity": "High",
        "description": "Prevents attackers from logging in directly as root.",
        "specificDetails": {
            "recommendation": "Set `PermitRootLogin no` in sshd_config."
        },
        "sources": [
            "OpenSSH Server Configuration",
            "CIS Benchmarks for SSH"
        ]
    }
]
