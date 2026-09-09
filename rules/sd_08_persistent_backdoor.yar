rule sd_08_persistent_backdoor {
    meta:
        id = "SD-08"
        class = "Persistent Backdoors"
        description = "Auto-loaded context files and persistent access mechanisms"
        severity = "HIGH"

    strings:
        $bashrc = ".bashrc" nocase
        $profile = ".profile" nocase
        $crontab = "crontab" nocase
        $systemd = "systemctl" nocase
        $autostart = "autostart" nocase
        $launchd = "LaunchAgent" nocase
        $startup = "startup" nocase

    condition:
        any of them
}
