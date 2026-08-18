// SD-05: Supply Chain Tampering
// Detects patterns related to supply chain attacks
// Adapted from Cisco Skill Scanner (Apache 2.0) and NVIDIA SkillSpector (MIT)

rule SD05_Dependency_Confusion
{
    meta:
        description = "Detects potential dependency confusion attacks"
        category = "SD-05 · Supply Chain Tampering"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $dep1 = /requirements.*\.txt/i
        $dep2 = /package.*\.json/i
        $dep3 = /pyproject\.toml/i
        $dep4 = /internal.*package/i

    condition:
        any of them
}

rule SD05_Hash_Mismatch
{
    meta:
        description = "Detects patterns that could indicate hash manipulation"
        category = "SD-05 · Supply Chain Tampering"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $hash1 = /sha256.*hash/i
        $hash2 = /checksum.*verify/i
        $hash3 = /hash.*mismatch/i

    condition:
        any of them
}

rule SD05_Typosquatting
{
    meta:
        description = "Detects potential typosquatting in package names"
        category = "SD-05 · Supply Chain Tampering"
        severity = "MEDIUM"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $typo1 = /requests\-requests/i
        $typo2 = /numpy\-numpy/i
        $typo3 = /pandas\-pandas/i
        $typo4 = /flask\-flask/i

    condition:
        any of them
}
