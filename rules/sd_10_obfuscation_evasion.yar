rule sd_10_obfuscation_evasion {
    meta:
        id = "SD-10"
        class = "Obfuscation and Evasion"
        description = "Homoglyph attacks, deferred payloads, logic bombs"
        severity = "HIGH"

    strings:
        $zwsp = { E2 80 8B }
        $zwnj = { E2 80 8C }
        $zwj = { E2 80 8D }
        $bidi_lro = { E2 80 AD }
        $bidi_rlo = { E2 80 AE }
        $bidi_lri = { E2 81 A6 }
        $bidi_rli = { E2 81 A7 }
        $base64_long = /[A-Za-z0-9+\/]{200,}={0,2}/
        $hex_encoded = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/

    condition:
        any of them
}
