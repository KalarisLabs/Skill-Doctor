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
        // Common Cyrillic lookalikes for Latin characters
        $homo1 = /[\u0430\u0410]/  // Cyrillic a/A vs Latin a/A
        $homo2 = /[\u0435\u0415]/  // Cyrillic e/E vs Latin e/E
        $homo3 = /[\u043E\u041E]/  // Cyrillic o/O vs Latin o/O
        $homo4 = /[\u0440\u0420]/  // Cyrillic r/R vs Latin r/R
        $homo5 = /[\u0441\u0421]/  // Cyrillic c/C vs Latin c/C

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
