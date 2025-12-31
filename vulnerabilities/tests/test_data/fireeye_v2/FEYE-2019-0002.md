# FEYE-2019-0002
## Description
GPU-Z.sys, part of the GPU-Z package from TechPowerUp, exposes the wrmsr instruction to user-mode callers without properly validating the target Model Specific Register (MSR). This can result in arbitrary unsigned code being executed in Ring 0.

## Impact
High - Arbitrary Ring 0 code execution

## Exploitability
Medium/Low - Driver must be loaded or attacker will require admin rights. Newer versions require admin callers.

## CVE Reference
CVE-2019-7245 

## Technical Details
IOCTL 0x8000644C in the GPU-Z driver instructs the binary to modify a Model Specific Register (MSR) on the target system. These registers control a wide variety of system functionality and can be used to monitor CPU temperature, track branches in code, tweak voltages, etc. MSRs are also responsible for setting the kernel mode function responsible for handling system calls.

The driver does not appropriately filter access to MSRs, allowing an attacker to overwrite the system call handler and run unsigned code in Ring 0. Allowing access to any of the following MSRs can result in arbitrary Ring 0 code being executed:

* 0xC0000081
* 0xC0000082
* 0xC0000083
* 0x174
* 0x175
* 0x176

For exploitation details see the INFILTRATE presentation in the references.

## Resolution
This issue is fixed in v2.23.0: [https://www.techpowerup.com/257995/techpowerup-releases-gpu-z-v2-23-0](https://www.techpowerup.com/257995/techpowerup-releases-gpu-z-v2-23-0)

## Discovery Credits
Ryan Warns

## Disclosure Timeline
- 2 February 2019 - Contacted vendor
- 2 February 2019 - Vendor response, confirmation of issue
- 25 July 2019 - Vendor confirmed fix
- 6 August 2019 - Fixed version released

## References 
[Exploitation Details](https://downloads.immunityinc.com/infiltrate2019-slidepacks/ryan-warns-timothy-harrison-device-driver-debauchery-msr-madness/MSR_Madness_v2.9_INFILTRATE.pptx)