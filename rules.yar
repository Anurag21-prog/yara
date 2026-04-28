rule Suspicious_Script_Commands
{
    meta:
        description = "Detects scripts trying to bypass execution policies or hide windows"
        severity = "Medium"
        
    strings:
        // 'nocase' means it ignores capitalization (e.g., matches "Hidden" or "hIdDeN")
        $ps1 = "ExecutionPolicy Bypass" nocase
        $ps2 = "-WindowStyle Hidden" nocase
        $cmd = "cmd.exe /c" nocase

    condition:
        // Triggers if ANY of the strings above are found in the file
        any of them
}

rule Is_Hidden_Executable
{
    meta:
        description = "Detects a Windows executable file (EXE/DLL)"
        
    strings:
        // 4D 5A in hex translates to 'MZ', the standard header for Windows executables
        $mz_header = { 4D 5A }
        
    condition:
        // Triggers ONLY if 'MZ' is found at the exact first byte (offset 0) of the file
        $mz_header at 0
}

rule Potential_Keylogger
{
    meta:
        description = "Looks for Windows executables containing keylogging API calls"
        severity = "High"

    strings:
        $api1 = "SetWindowsHookEx" ascii wide
        $api2 = "GetAsyncKeyState" ascii wide
        $api3 = "GetKeyboardState" ascii wide
        
    condition:
        // 1. It must be an executable file (uint16(0) reads the first 2 bytes)
        // 0x5A4D is 'MZ' in little-endian format
        uint16(0) == 0x5A4D 
        
        // 2. The file must be smaller than 5 Megabytes (avoids scanning huge games/apps)
        and filesize < 5MB 
        
        // 3. It must contain at least 2 of the suspicious API calls
        and 2 of ($api*)
}