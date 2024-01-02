# Apache OFBiz Authentication Bypass Vulnerability (CVE-2023-51467 and CVE-2023-49070)

This exploit script and PoC is written for an indept CVE analysis on [vsociety](https://www.vicarius.io/vsociety/).

The Apache OFBiz Enterprise Resource Planning (ERP) system, a versatile Java-based web framework widely utilized across industries, is facing a critical security challenge. The SonicWall Threat research team's [discovery](https://blog.sonicwall.com/en-us/2023/12/sonicwall-discovers-critical-apache-ofbiz-zero-day-authbiz/) of CVE-2023-51467, a severe authentication bypass vulnerability with a CVSS score of 9.8, has unveiled an alarming risk to the system's integrity. This vulnerability not only exposes the ERP system to potential exploitation but also opens the door to a Server-Side Request Forgery (SSRF) exploit, presenting a dual threat to organizations relying on Apache OFBiz.

The repo also contains [ysoserail](https://github.com/frohoff/ysoserial) release that is used to generate a serialized data.

## Usage

Run script in scanner mode:

```bash
python3 exploit.py --url https://localhost:8443
```

Run command on the remote server:
```bash
python3 exploit.py --url https://localhost:8443 --cmd 'CMD'
```

## Disclaimer
This exploit script has been created solely for the purposes of research and for the development of effective defensive techniques. It is not intended to be used for any malicious or unauthorized activities. The author and the owner of the script disclaim any responsibility or liability for any misuse or damage caused by this software. Users are urged to use this software responsibly and only in accordance with applicable laws and regulations. Use responsibly.
