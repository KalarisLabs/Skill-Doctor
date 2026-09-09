rule sd_04_privilege_escalation {
    meta:
        id = "SD-04"
        class = "Privilege Escalation / Scope Violation"
        description = "Undeclared capability usage or scope violation"
        severity = "HIGH"

    strings:
        $sudo = "sudo " nocase
        $chmod_suid = "chmod +s" nocase
        $chmod_777 = "chmod 777" nocase
        $su_root = "su root" nocase
        $admin_api = /\/admin\//i
        $escalate = "privilege" nocase

    condition:
        any of them
}
