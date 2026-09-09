rule sd_07_tool_poisoning {
    meta:
        id = "SD-07"
        class = "Tool Poisoning"
        description = "Tool name collision / shadowing"
        severity = "MEDIUM"

    strings:
        $tool_override = "tool_name:" nocase
        $name_collision = "override" nocase
        $shadow_tool = "shadow" nocase
        $replace_tool = "replace_tool" nocase

    condition:
        2 of them
}
