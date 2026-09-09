rule sd_11_scanner_mediated_injection {
    meta:
        id = "SD-11"
        class = "Scanner-Mediated Injection"
        description = "Content designed to inject into the scanner itself or its model pipeline"
        severity = "CRITICAL"

    strings:
        $inject_scanner = "skill-doctor" nocase
        $inject_prompt = "scanning agent" nocase
        $model_inject = "as a language model" nocase
        $system_prompt = "system prompt" nocase
        $xml_inject = "<tool_call>" nocase
        $function_inject = "function_call" nocase

    condition:
        2 of them
}
