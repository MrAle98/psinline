# psinline

BOF for executing powershell directly in current process memory, avoiding process injections. Takes as input PS.exe, an assembly running base64-encoded powershell commands. Code mostly taken from [Havoc](https://github.com/HavocFramework/Havoc),
for hardware breakpoints and [InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly) for running assemblies through BOF.

## How it works 

Takes as input the following parameters:
1. PS.exe. Assembly that executes base64 encoded powershell
2. Powershell script. A powershell script. In case you don't need to provide it, just you can create a dummy powershell script with just one line.
3. powershell command.

The BOF concatenates your powershell command to the powershell script, base64 encode the concatenation and finally pass the base64 blob as argument to PS.exe that executes it. It uses hardware breakpoints for AMSI/ETW bypass.

## How to build

For building the BOF just run:
```
make -f MakeFile release
```

For building the debug version run:
```
make -f MakeFile debug
```

For building PS.exe import it in visual studio and compile release version.


## Pre-Compiled binaries

Pre-compiled binaries are available in the release package.

## Examples

### Run PowerView cmdlet

First use coff_args to set PowerView.ps1 as powershell script to load and then use coffexec to execute **Get-NetLocalGroup**:
```
=> set_coffargs /path/to/PS.exe /path/to/PowerView.ps1

2023/09/25 13:51:49 CEST [sent 1842868 bytes]

[*] CoffExec Arguments Updated
+-------------------------------------------------------------------+
=> coffexec /path/to/psinline.x64.o Get-NetLocalGroup | fl *

2023/09/25 13:52:35 CEST [sent 41592 bytes]

[*] Task-0 [Thread: 6164]

[*] Coffexec Output:

[*] Using .NET version v4.0.30319



ComputerName : DESKTOP-URP43TK
GroupName    : Access Control Assistance Operators
Comment      : Members of this group can remotely query authorization attributes and permissions for resources on this 
               computer.

ComputerName : DESKTOP-URP43TK
GroupName    : Administrators
Comment      : Administrators have complete and unrestricted access to the computer/domain

[...]

[+] psinline Finished

```

![image](https://github.com/MrAle98/psinline/assets/74059030/29b96742-c21f-43df-a2a7-a310ca0b7c66)

### Run generic powershell command

Set script to import a dummy powershell script and then run **ls** command with coffexec. You can find an example of dummy powershell script in the release package, named dummy.ps1:
```
=> set_coffargs /path/to/PS.exe /path/to/dummy.ps1 

2023/09/25 14:28:26 CEST [sent 17032 bytes]

[*] CoffExec Arguments Updated
+-------------------------------------------------------------------+
=> coffexec /home/kali/CLionProjects/psinline/psinline.x64.o ls
[*] Coffexec Output:

[*] Using .NET version v4.0.30319



    Directory: C:\temp\inceptor\inceptor\inceptor


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
d-----         5/23/2023  12:07 AM                artifacts                                                             
d-----         5/23/2023  12:07 AM                certs                                                                 
d-----         6/11/2023   9:14 AM                compilers                                                             
d-----          6/2/2023   5:00 PM                config                                                                
d-----          6/2/2023   5:00 PM                converters                                                            
d-----          6/2/2023   5:00 PM                demo
[...]

[+] psinline Finished
```

![image](https://github.com/MrAle98/psinline/assets/74059030/39521fbc-a5e9-4b8e-afae-740001525c13)

## Notes

Everytime you launch psinline, **wait for it to finish before launching it again**. Having **two threads running psinline at same time will break things and kill your process**.

## Credits
- [@C5pider](https://github.com/Cracked5pider)
- [@anthemtotheego](https://github.com/anthemtotheego)
