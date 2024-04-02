 ##https://os.cybbh.io/public/os/latest/index.html (student guide)
    
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
