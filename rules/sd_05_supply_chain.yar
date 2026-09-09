rule sd_05_supply_chain_tampering {
    meta:
        id = "SD-05"
        class = "Supply-Chain Tampering"
        description = "Checksum manipulation, bytecode cache poisoning, typosquatting"
        severity = "HIGH"

    strings:
        $pip_install = /pip install\s+[a-z]/ nocase
        $npm_install = /npm install\s+[a-z]/ nocase
        $curl_pipe_bash = /curl\s+.*\|\s*(ba)?sh/ nocase
        $wget_pipe = /wget\s+.*\|\s*(ba)?sh/ nocase
        $checksum_override = "md5sum" nocase
        $pyc_cache = "__pycache__" nocase

    condition:
        any of them
}
