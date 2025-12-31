# MNDT-2025-0009

## Description
Improper verification of cryptographic signature in the installer for Zoom Workplace VDI Client for Windows may allow an authenticated user to conduct an escalation of privilege via local access.

## Impact
Medium: Executing untrusted, unsigned code can aid an adversary in bypassing endpoint security controls such as application whitelisting or endpoint detection and response products. It can also lead to the compromise of the VDI Client entirely.

## Exploitability
High: Adversaries need standard user access to a system with the affected version of Zoom's Workplace VDI client for Windows installed.

## CVE ID
[CVE-2025-64740](https://www.cve.org/CVERecord?id=CVE-2025-64740)

## Common Weakness Enumeration
CWE-347: Improper Verification of Cryptographic Signature

## Details
The Zoom VDI Client attempted to load a DLL named WFAPI64.dll which does not exist on a system as part of the standard installation process. Additionally, a path formatting issue also existed where the directory name of the user's PATH variable is appended to the name of the DLL to search for which led to a unique DLL load attempt upon every execution. The Zoom Client also did not verify the signature of the DLL when loaded.

By crafting a specific DLL and making a modification to the PATH variable, it's possible to execute unauthorized, unsigned code in the context of Zoom's VDI Client.

## Resolution
Upgrade to Zoom Workplace VDI Client for Windows, versions 6.3.14, 6.4.12 and 6.5.10 or greater in their respective tracks.

## Discovery Credits
* Cory Baker, Mandiant

## Disclosure Timeline
* July 24, 2025: Initial report to the Zoom Vulnerability Disclosure team
* August 8, 2025: Issue confirmed by Zoom's engineering team
* September 5, 2025: Zoom released Workspace VDI Client v6.5.10
* November 11, 2025: Zoom Security Bulletin issued

## References
* https://www.zoom.com/en/trust/security-bulletin/zsb-25042/
* https://www.cve.org/CVERecord?id=CVE-2025-64740

