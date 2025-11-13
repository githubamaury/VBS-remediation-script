Many Windows components can trigger VBS activation. This "vbsremediation_verbose_... .ps1" Powershell script checks and disables them. This can be useful if for example you want to run ESX in Vmware Workstation Pro for lab use. Please let me know of any issues. It automatically creates a restore point to solve system issues if any would appear.

I don't take any credit for it since it was mostly AI generated, but one still has to give the right input to the AI, check all possible VBS triggers in Windows, remediate any errors the AI makes, optimize the script and test run on multiple machines. 

12/11/2025: a restore script has been added.

12/11/2025: a full diagnostics sccript has been added before disabling anything.

12/11/2025: I added an extra method to disable vbs by editing the efi loader (ESP partition detected automatically). This should only be run after the default "vbsremediation_verbose_enhanced_restorepoint.ps1" script and will for now only work until the next reboot. 
