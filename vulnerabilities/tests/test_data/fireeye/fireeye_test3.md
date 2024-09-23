# MNDT-2023-0017

The IBM Personal Communications (PCOMM) application 13.0.0 and earlier caused a user's plaintext password to be written to the `C:\Temp\pcsnp_init.log` file when re-connection was made through a remote desktop protocol.

## Common Weakness Enumeration
CWE-312: Cleartext Storage of Sensitive Information

## Impact
High - An attacker with low-privilege access to a host with IBM PCOMM could recover the plaintext password of another user.

## Exploitability
Low - Exploitability varies depending on the environment in which IBM PCOMM is installed. Mandiant identified this vulnerability when conducting independent security research for a client that used Citrix to connect to shared Windows Server instances. In certain environments where remote desktop is used to connect to shared hosts with IBM PCOMM installed, the exploitability is greatly increased.

## CVE Reference
CVE-2016-0321 - scope expanded

## Technical Details
While conducting independent security research, Mandiant identified a plaintext Active Directory password stored within the `C:\Temp\pcsnp_init.log` file. The affected host had IBM PCOMM version 13.0.0 installed and was used by multiple users who connected with Citrix. Upon a user connecting, disconnecting, and connecting again, the user's plaintext password was stored in the `C:\Temp\pcsnp_init.log` file.

## Discovery Credits
- Adin Drabkin, Mandiant
- Matthew Rotlevi, Mandiant

## Disclosure Timeline
- 2023-09-26 - Issue reported to the vendor.
- 2023-11-03 - The vendor updated the security bulletin for CVE-2016-0321 to include all known affected and fixed versions.

## References
- [IBM Security Bulletin](https://www.ibm.com/support/pages/security-bulletin-ibm-personal-communications-could-allow-remote-user-obtain-sensitive-information-including-user-passwords-allowing-unauthorized-access-cve-2016-0321)
- [IBM Personal Communications](https://www.ibm.com/support/pages/ibm-personal-communications)
- [Mitre CVE-2016-0321](https://www.cve.org/CVERecord?id=CVE-2016-0321)
