 ##https://os.cybbh.io/public/os/latest/index.html (student guide)

     stack number = 9
     ip = 10.50.25.139 ADMIN IP
     http://10.50.22.197:8000/ CTFD IP
     LUMC-M-502
    
    xfreerdp /u:student /v:10.50.34.195 /dynamic-resolution +glyph-cache +clipboard (use this command to get into the system)

 ## open powershell, run as admin **POWERSHELL COMMANDS**

    **commands:**
    **pwsh** - gets you powershell version
    **history** - shows commands you've used
    **get-member** - shows properties, methods and definitions for command
    **get-process** - shows running processes.
     **example of using get process**  get-process | select name,id,starttime
    **get-content** - to read a file
    **get-alias** - shows aliases of cmdlets
    **get-help** - gives you a help page. ex: get-help get-process
    **get-location / pwd** - shows current working directory
    **whoami** - shows who you're logged in as on box
    **dot notation:**
    get-process | select name
    (get-process).name
    **start processes** - notepad.exe (opens notepad)
    start-process notepad
    stop-process -name notepad
    or
    start-process chrome
    (get-process chrome*).kill()
    
    get-process | get-member | where-object {$_.membertype -match "method"}
    only pulling method's from the output of get-member

    get-process | select name, id, path | where {$_.id -lt '1000'}
    shows processes with an id less than 1000

    get-host - shows version of powershell you're using

    measure-object - counting lines in a file, summing, averaging
    select-string - search for text patterns in a string

    get-alias -definition Get-childitem (shows all aliases for get childitem)

     Get-CimInstance win32_service | ?{$_.Name -like 'LegoLand'} | select Description ((shows description of service))

      Compare-object (get-content new.txt) (get-content old.txt) ((compares difference between two text file))

     (get-content words.txt | Select-String -pattern "a","z").length ((counts number of times a or z appears in a word in the text file

     attached drives cli - fsutil fsinfo drives
     
 ## transcripts

    start-transcript
     ** enter commands here **
     stop-transcript
     ** then navigate to location and view/rename transcript **


 ## CIM Classes
    use this command when dealing with things like bios, or other physical things on machine.
    get-cimclass *
     shows all of your cim classes
    get-ciminstance -class win32_bios
     shows all of your bios information

 ## adding and removing items

    new-item does_not_exist.txt (-erroraction SilentlyContinue)
    remove-item does_not_exist.txt (-verbose)
## variables
    get-variable - shows variables
    $processes = get-processes
 
    $today = (get-date).datetime
    $today
    Tuesday, April 2, 2024 1:04:08 PM
    remove-variable -name today
    or clear variable by using
    clear-variable -name today

## wildcards
    if using wildcards * before or after, use -match(matches or when using regex) or -like(looking for   something similar)

## execution policy
    get-executionpolicy
    set-executionpolicy -executionpolicy unrestricted -scope currentuser
    get-executionpolicy
    unrestricted

## windows persistence mechanisms
    powershell profiles - 
     highest order of presidence = all users, all hosts - if this profile setting is set, it'll apply to all users, all hosts.
     all users, current host - if this is set, the profile will be set to all users on current machine
     current user, all hosts - if this is set, it applies to a current user on all machines
     current user, current host - applies to one user on one host.

     how to check = test-path -path $profile.currentusercurrenthost

     if it comes back true, 'cat' the command as seen above.

     $profile - tells us where the current profile is stored at
     
## linux persistence mechanisms


## Windows Registry

    HKLM - HKEY_LOCAL_MACHINE
      HARDWARE - contains a database of installed devices along with their drivers
      SAM - Security Account Manager stores user and group accounts along with NTLM hashes of passwords
      Security - Local Security policy accessed by lsass.exe used to determine rights and permissions for users on the machine
      System - Contains keys pertaining to system startup such as programs started on boot or driver load order.
      
    HKU - HKEY_USERS
     contains user profiles on system. one key per user, each key is named after the SID of the user
     
    HKCU - HKEY_CURRENT_USERS
      is the copy of the logged in user’s registry key based on thier SID from HKEY_USERS.
    HKCC - HKEY_CURRENT_CONFIG
    
    HKCR - HKEY_CLASSES_ROOT

    All hives in HKLM are stored in %SYSTEMROOT%\System32\config\ (%SYSTEMROOT% usually refers to C:\WINDOWS).

    view/manipulate registry - regedit.exe
## manipulating registry in cmd

    ex: opening registry in command line
    reg query HKLM\software\microsoft\windows\currentversion\run
    reg add HKLM\SOFTWARE\microsoft\windows\currentversion\run /v testme /t REG_SZ /d C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v testme

## manipulating registry in powershell

    Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run ((reads sub keys from input value))
    Get-item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run ((reads value of inputted object))
    New-Item "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Force ((creates new sub key associated with hive))
    
    New-ItemProperty "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Name "%USERPROFILE%Downloads/test-document.doc" -PropertyType Binary -Value ([byte[]](0x30,0x31,0xFF)) 

     New-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Test -PropertyType String -Value C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 

      Get-LocalUser | select Name, sid ((to see local users & sids in powershell))

## PSDrives

    Get-PSDrive ((find current PSDrives))
    New-PSDrive -PSProvider Registry -name HKU -Root HKEY_USERS ((add a drive))
    https://os.cybbh.io/public/os/latest/004_windows_registry/reg_fg.html

## Alternate Data Streams 

    https://os.cybbh.io/public/os/latest/005_windows_ads/ads_fg.html
    echo Always try your best > reminder.txt
    echo social security numbers > reminder.txt:secret.info ((adds social security numbers to reminder .txt in ADS))
    more < reminder.txt:secret.info ((to view hidden ADS))
    or
    notepad reminder.txt:secret.info

    To determine if there is an ADS do:
    dir /R

  ## Linux Essentials
  
     https://os.cybbh.io/public/os/latest/003_linux_essentials/bash_fg.html
     netstat -ano         to look at connections / ports
     pivot from port opening an executable - netstat -ano ((sudo netstat -ltup))
     ~ home directory
     / root directory
     file permissions       user,group,owner
     help information ls -- help
     or 
     man ls
     variables in linux:     a="100"       directories=$(ls /)
                             echo $a       echo $directories
                             100
     
     redirection -           echo $directories 1> thisisanewfile
     0 - standard input      cat thisisanewfile ((opens up your ls output from above))
     1 - standard output
     2 - standard error      ls bacon 2>/dev/null ((bacon doesnt exist, sends error message to the void))

     piping -                ls -Rlisa /etc | grep syslog ((R means recursive, grep is to search for a string)) 

     looping -                objects=$(ls -d /etc/*)
                              echo $objects
                              for item in $objects; do echo $item; done
                              or 
                              for object in $objects; do if [ -d $object ]; then echo "$object is a directory"; else echo "$object is a file" ; fi ; done

## Linux File Systems

    /bin directory - contains system binaries (commands like ls and echo)
    /home - contains directories for non root users
    /etc - contains configuration files, network configs, system services, firewall stuff etc
    /var - contains variable data, system logs etc.

    id - command that shows user id, group id etc. 
    cat /etc/passwd - also shows user information (might have to sudo it)
    ex: sudo cat /etc/passwd | grep garviel

    ex: man -k "digest"            searches man pages for something containing digest

    find ip's in a file:            cat numbers.txt | grep -Po '^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$' | wc -l


 ## Windows Boot Process

    https://os.cybbh.io/public/os/latest/006_windows_boot_process/winboot_fg.html
    
    lsass.exe - the Local Security Authority Subsystem (LSASS) provides user authentication services, manages the local security policy, and generates access tokens.

    services.exe the Services Control Manager (SCM) loads AutoStart services, using LSASS to authenticate if they run as something other than System.

    Ways to check services - 
     reg query hkey_local_machine\system\currentcontrolset\services\Spooler
     tasklist /svc

     bcdedit
     bcdedit /set {current} description "this is a description" ((to change something in bcd)
     
     To add stuff to bcd --
     bcdedit /create {ntldr} /d "win XP" -> bcdedit /set {ntldr} device partition=C: -> bcdedit /set {ntldr} path \downloads -> bcdedit /displayorder {ntldr} /addfirst

     to delete stuff from bcd --
     bcdedit /delete {ntldr} /f

     to restore backup -- 
     bcdedit /import C:\bcd.bk
    


     
    
     

     
    
    

  

  
