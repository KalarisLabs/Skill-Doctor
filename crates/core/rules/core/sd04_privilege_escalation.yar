// SD-04: Privilege Escalation
// Detects patterns that could lead to privilege escalation
// Adapted from Cisco Skill Scanner (Apache 2.0) and NVIDIA SkillSpector (MIT)

rule SD04_Tool_Scope_Violation
{
    meta:
        description = "Detects tool registration with excessive permissions"
        category = "SD-04 · Privilege Escalation"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $tool1 = /tool.*filesystem.*read/i
        $tool2 = /tool.*execute.*command/i
        $tool3 = /tool.*network.*access/i
        $tool4 = /permission.*admin/i
        $tool5 = /scope.*all.*files/i

    condition:
        any of them
}

rule SD04_Cross_Tool_Attack
{
    meta:
        description = "Detects potential cross-tool attack patterns"
        category = "SD-04 · Privilege Escalation"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $cross1 = /context.*window.*poison/i
        $cross2 = /agent.*impersonate/i
        $cross3 = /tool.*override.*trusted/i

    condition:
        any of them
}
