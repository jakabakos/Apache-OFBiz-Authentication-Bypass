# Apache OFBiz Authentication Bypass Vulnerability (CVE-2023-51467 and CVE-2023-49070)

This exploit script and PoC are written for an in-depth CVE analysis on [vsociety](https://www.vicarius.io/vsociety/).

The Apache OFBiz Enterprise Resource Planning (ERP) system, a versatile Java-based web framework widely utilized across industries, is facing a critical security challenge. The SonicWall Threat research team's [discovery](https://blog.sonicwall.com/en-us/2023/12/sonicwall-discovers-critical-apache-ofbiz-zero-day-authbiz/) of CVE-2023-51467, a severe authentication bypass vulnerability with a CVSS score of 9.8, has unveiled an alarming risk to the system's integrity. This vulnerability not only exposes the ERP system to potential exploitation but also opens the door to a Server-Side Request Forgery (SSRF) exploit, presenting a dual threat to organizations relying on Apache OFBiz.

The repo also contains [ysoserial](https://github.com/frohoff/ysoserial) release used to generate serialized data.

## Usage

Run the script in scanner mode:

```bash
python3 exploit.py --url https://localhost:8443
```

Run command on the remote server:
```bash
python3 exploit.py --url https://localhost:8443 --cmd 'CMD'
```

## Disclaimer
This exploit script has been created solely for research and the development of effective defensive techniques. It is not intended to be used for any malicious or unauthorized activities. The script's author and owner disclaim any responsibility or liability for any misuse or damage caused by this software. Just so you know, users are urged to use this software responsibly and only by applicable laws and regulations. Use responsibly.
