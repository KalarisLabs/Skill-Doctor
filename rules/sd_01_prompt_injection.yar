rule sd_01_prompt_injection_direct {
    meta:
        id = "SD-01"
        class = "Prompt Injection"
        description = "Direct prompt injection via instruction override text"
        severity = "HIGH"

    strings:
        $ignore1 = "ignore previous instructions" nocase
        $ignore2 = "ignore all previous" nocase
        $ignore3 = "disregard your instructions" nocase
        $override1 = "SYSTEM OVERRIDE" nocase
        $override2 = "new instructions:" nocase
        $override3 = "you are now" nocase
        $jailbreak1 = "DAN mode" nocase
        $jailbreak2 = "developer mode" nocase

    condition:
        any of them
}
