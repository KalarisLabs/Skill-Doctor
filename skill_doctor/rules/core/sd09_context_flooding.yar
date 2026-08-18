// SD-09: Context Window Flooding
// Detects patterns that could lead to context window flooding
// Adapted from Cisco Skill Scanner (Apache 2.0) and NVIDIA SkillSpector (MIT)

rule SD09_Large_Output_Generation
{
    meta:
        description = "Detects patterns that could generate excessively large outputs"
        category = "SD-09 · Context Window Flooding"
        severity = "MEDIUM"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $large1 = /repeat.*\d+.*times/i
        $large2 = /generate.*\d+.*lines/i
        $large3 = /output.*maximum/i
        $large4 = /print.*loop/i

    condition:
        any of them
}

rule SD09_Context_Dump_Request
{
    meta:
        description = "Detects requests for full context or conversation history"
        category = "SD-09 · Context Window Flooding"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $dump1 = /full.*conversation/i
        $dump2 = /context.*window.*all/i
        $dump3 = /history.*complete/i
        $dump4 = /system.*prompt.*show/i

    condition:
        any of them
}
