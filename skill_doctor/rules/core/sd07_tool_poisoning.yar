// SD-07: Tool Poisoning
// Detects shadow tool registration and parameter schema manipulation
// Adapted from Cisco Skill Scanner (Apache 2.0) and NVIDIA SkillSpector (MIT)

rule SD07_Shadow_Tool_Registration
{
    meta:
        description = "Detects shadow tool registration (same name as trusted tool)"
        category = "SD-07 · Tool Poisoning"
        severity = "CRITICAL"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $shadow1 = /tool.*bash.*override/i
        $shadow2 = /tool.*python.*custom/i
        $shadow3 = /tool.*npm.*modified/i
        $shadow4 = /register.*tool.*existing/i

    condition:
        any of them
}

rule SD07_Parameter_Schema_Manipulation
{
    meta:
        description = "Detects parameter schema manipulation"
        category = "SD-07 · Tool Poisoning"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $schema1 = /parameter.*description.*alter/i
        $schema2 = /schema.*modify.*behavior/i
        $schema3 = /tool.*name.*same.*different/i

    condition:
        any of them
}
