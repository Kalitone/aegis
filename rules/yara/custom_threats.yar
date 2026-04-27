/*
    AEGIS Custom YARA Rules
    =========================
    Additional rules beyond the built-in set.
    These target common real-world threats.
*/

rule linux_rootkit_indicators {
    meta:
        description = "Common Linux rootkit artifacts"
        severity = "critical"
        mitre = "T1014"
        author = "aegis"
    strings:
        $s1 = "proc_readdir" ascii
        $s2 = "module_hide" ascii
        $s3 = "rootkit" ascii nocase
        $s4 = "hide_pid" ascii
        $s5 = "intercept_syscall" ascii
        $s6 = "sys_call_table" ascii
    condition:
        3 of them
}

rule suspicious_python_payload {
    meta:
        description = "Python script with shellcode/injection patterns"
        severity = "high"
        mitre = "T1059.006"
        author = "aegis"
    strings:
        $py = "import " ascii
        $s1 = "ctypes.windll" ascii
        $s2 = "ctypes.CDLL" ascii
        $s3 = "mmap.MAP" ascii
        $s4 = "\\x90\\x90" ascii
        $s5 = "shellcode" ascii nocase
        $s6 = "VirtualAlloc" ascii
        $s7 = "CreateRemoteThread" ascii
        $s8 = "NtAllocateVirtualMemory" ascii
    condition:
        $py and 2 of ($s*)
}

rule ransomware_note {
    meta:
        description = "Ransomware ransom note indicators"
        severity = "critical"
        mitre = "T1486"
        author = "aegis"
    strings:
        $r1 = "your files have been encrypted" ascii nocase
        $r2 = "bitcoin" ascii nocase
        $r3 = "decrypt" ascii nocase
        $r4 = "ransom" ascii nocase
        $r5 = "pay" ascii nocase
        $r6 = "wallet" ascii nocase
        $r7 = ".onion" ascii
        $ext1 = ".locked" ascii
        $ext2 = ".encrypted" ascii
        $ext3 = ".crypt" ascii
    // Original condition (kept for reference, replaced below):
    //     3 of ($r*) or (any of ($ext*) and 2 of ($r*))
    condition: false and any of them  // DISABLED 2026-04-24: see analysis_reports/01_security.md - produced 100% FP rate; broke condition fires on plain English text. Re-enable only after adding PE/ELF magic gating and removing single-token strings. (`false and any of them` keeps all string defs referenced so yara-python compiles cleanly while still never matching.)
}

rule suspicious_powershell_script {
    meta:
        description = "Obfuscated PowerShell with execution patterns"
        severity = "high"
        mitre = "T1059.001"
        author = "aegis"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase
        $e1 = "-encodedcommand" ascii nocase
        $e2 = "-enc " ascii nocase
        $e3 = "FromBase64String" ascii nocase
        $e4 = "Invoke-Expression" ascii nocase
        $e5 = "IEX(" ascii nocase
        $e6 = "iex " ascii nocase
        $e7 = "Invoke-Mimikatz" ascii nocase
        $e8 = "Invoke-Shellcode" ascii nocase
        $e9 = "-nop -w hidden" ascii nocase
        $e10 = "bypass" ascii nocase
        $d1 = "DownloadString" ascii nocase
        $d2 = "DownloadFile" ascii nocase
        $d3 = "Net.WebClient" ascii nocase
        $d4 = "Invoke-WebRequest" ascii nocase
    condition:
        (any of ($ps*)) and (2 of ($e*) or (any of ($e*) and any of ($d*)))
}

rule data_exfil_tool {
    meta:
        description = "Data exfiltration utility indicators"
        severity = "high"
        mitre = "T1048"
        author = "aegis"
    strings:
        $t1 = "rclone" ascii nocase
        $t2 = "megacmd" ascii nocase
        $t3 = "s3cmd" ascii nocase
        $t4 = "winscp" ascii nocase
        $t5 = "filezilla" ascii nocase
        $c1 = "transfer.sh" ascii
        $c2 = "file.io" ascii
        $c3 = "0x0.st" ascii
        $c4 = "paste.ee" ascii
    // Original condition (kept for reference, replaced below):
    //     any of them
    condition: false and any of them  // DISABLED 2026-04-24: see analysis_reports/01_security.md - produced 100% FP rate; broke condition fires on plain English text. Re-enable only after adding PE/ELF magic gating and removing single-token strings. (`false and any of them` keeps all string defs referenced so yara-python compiles cleanly while still never matching.)
}

rule credential_harvester {
    meta:
        description = "Credential harvesting tool patterns"
        severity = "critical"
        mitre = "T1003"
        author = "aegis"
    strings:
        $m1 = "mimikatz" ascii nocase
        $m2 = "sekurlsa::logonpasswords" ascii nocase
        $m3 = "lsadump::sam" ascii nocase
        $l1 = "LaZagne" ascii nocase
        $l2 = "password" ascii nocase
        $l3 = "credential" ascii nocase
        $h1 = "hashdump" ascii nocase
        $h2 = "pwdump" ascii nocase
        $h3 = "fgdump" ascii nocase
        $k1 = "keylog" ascii nocase
    // Original condition (kept for reference, replaced below):
    //     any of ($m*) or any of ($l*) or any of ($h*) or $k1
    condition: false and any of them  // DISABLED 2026-04-24: see analysis_reports/01_security.md - produced 100% FP rate; broke condition fires on plain English text. Re-enable only after adding PE/ELF magic gating and removing single-token strings. (`false and any of them` keeps all string defs referenced so yara-python compiles cleanly while still never matching.)
}

rule suspicious_npm_package {
    meta:
        description = "Suspicious npm package.json with install scripts"
        severity = "medium"
        mitre = "T1195.001"
        author = "aegis"
    strings:
        $pkg = "\"name\":" ascii
        $s1 = "preinstall" ascii
        $s2 = "postinstall" ascii
        $e1 = "child_process" ascii
        $e2 = "exec(" ascii
        $e3 = "eval(" ascii
        $e4 = "curl " ascii
        $e5 = "wget " ascii
        $n1 = "net.connect" ascii
        $n2 = "http.request" ascii
    condition:
        $pkg and (any of ($s*)) and (any of ($e*) or any of ($n*))
}
