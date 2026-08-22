// SD-10: Obfuscation and Evasion
// Detects patterns used to evade detection
// Adapted from Cisco Skill Scanner (Apache 2.0) and NVIDIA SkillSpector (MIT)

rule SD10_Homoglyph_Substitution
{
    meta:
        description = "Detects homoglyph substitution (Cyrillic vs Latin characters)"
        category = "SD-10 · Obfuscation and Evasion"
        severity = "MEDIUM"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        // Common Cyrillic lookalikes for Latin characters (UTF-8 byte matches)
        $homo1 = /\xd0\xb0|\xd0\x90/  // Cyrillic a/A
        $homo2 = /\xd0\xb5|\xd0\x95/  // Cyrillic e/E
        $homo3 = /\xd0\xbe|\xd0\x9e/  // Cyrillic o/O
        $homo4 = /\xd1\x80|\xd0\xa0/  // Cyrillic r/R
        $homo5 = /\xd1\x81|\xd0\xa1/  // Cyrillic c/C

    condition:
        any of them
}

rule SD10_Encoded_Payloads
{
    meta:
        description = "Detects encoded payloads (base64, hex, rot13)"
        category = "SD-10 · Obfuscation and Evasion"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $encode1 = "base64" nocase
        $encode2 = "b64decode" nocase
        $encode3 = "rot13" nocase
        $encode4 = "hex_decode" nocase
        $encode5 = /\\x[0-9a-f]{2}/i  // Hex escape sequences

    condition:
        any of them
}

rule SD10_Deferred_Execution
{
    meta:
        description = "Detects deferred payload fetch or execution"
        category = "SD-10 · Obfuscation and Evasion"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $defer1 = /download.*execute/i
        $defer2 = /fetch.*run/i
        $defer3 = /eval.*download/i
        $defer4 = /import.*remote/i

    condition:
        any of them
}

rule SD10_Logic_Bomb
{
    meta:
        description = "Detects conditional execution (logic bombs)"
        category = "SD-10 · Obfuscation and Evasion"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $logic1 = /if.*time.*>.*\d+/i
        $logic2 = /if.*date.*==/i
        $logic3 = /environment.*check/i
        $logic4 = /condition.*trigger/i

    condition:
        any of them
}
