rule sd_02_command_injection {
    meta:
        id = "SD-02"
        class = "Command Injection"
        description = "Command injection via companion scripts"
        severity = "HIGH"

    strings:
        $eval_var = /eval\s+\$/ nocase
        $eval_paren = "eval(" nocase
        $curl_subshell = "$(curl" nocase
        $wget_subshell = "$(wget" nocase
        $backtick_curl = "`curl" nocase
        $backtick_wget = "`wget" nocase
        $os_system = "os.system(" nocase
        $subprocess_call = "subprocess.call(" nocase
        $subprocess_run = "subprocess.run(" nocase
        $child_process = "child_process" nocase
        $exec_call = /\bexec\s*\(/ nocase

    condition:
        any of them
}
