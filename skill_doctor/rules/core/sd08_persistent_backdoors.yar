// SD-08: Persistent Backdoors
// Detects patterns that could lead to persistent backdoors
// Adapted from Cisco Skill Scanner (Apache 2.0) and NVIDIA SkillSpector (MIT)

rule SD08_Auto_Loaded_File_Writes
{
    meta:
        description = "Detects writes to auto-loaded context files"
        category = "SD-08 · Persistent Backdoors"
        severity = "CRITICAL"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $file1 = "CLAUDE.md" nocase
        $file2 = ".cursor/rules" nocase
        $file3 = ".github/copilot-instructions.md" nocase
        $file4 = ".cursorrules" nocase
        $file5 = "AGENTS.md" nocase

    condition:
        any of them
}

rule SD08_Modify_Other_Skills
{
    meta:
        description = "Detects attempts to modify other skill files"
        category = "SD-08 · Persistent Backdoors"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $modify1 = /write.*skill.*file/i
        $modify2 = /modify.*SKILL\.md/i
        $modify3 = /overwrite.*agent/i

    condition:
        any of them
}

rule SD08_Startup_Scripts
{
    meta:
        description = "Detects installation of startup scripts or cron jobs"
        category = "SD-08 · Persistent Backdoors"
        severity = "CRITICAL"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $startup1 = "cron" nocase
        $startup2 = "systemd" nocase
        $startup3 = "startup" nocase
        $startup4 = "launchd" nocase
        $startup5 = "autostart" nocase

    condition:
        any of them
}
