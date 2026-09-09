rule sd_09_context_flooding {
    meta:
        id = "SD-09"
        class = "Context-Window Flooding"
        description = "Excessive content designed to flood the context window"
        severity = "MEDIUM"

    strings:
        $repeat_a = /(.{1,10})\1{50,}/
        $long_base64 = /[A-Za-z0-9+\/]{500,}/
        $padding = /\s{1000,}/

    condition:
        any of them
}
