// SD-03: Data Exfiltration
// Detects patterns that could lead to data exfiltration
// Adapted from Cisco Skill Scanner (Apache 2.0) and NVIDIA SkillSpector (MIT)

rule SD03_Environment_Variable_Harvesting
{
    meta:
        description = "Detects access to sensitive environment variables"
        category = "SD-03 · Data Exfiltration"
        severity = "CRITICAL"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $env1 = "os.environ['AWS_SECRET_ACCESS_KEY']" nocase
        $env2 = "os.environ['AWS_ACCESS_KEY_ID']" nocase
        $env3 = "os.environ['GITHUB_TOKEN']" nocase
        $env4 = "os.environ['API_KEY']" nocase
        $env5 = "os.environ['PASSWORD']" nocase
        $env6 = "os.environ['TOKEN']" nocase

    condition:
        any of them
}

rule SD03_Sensitive_Path_Access
{
    meta:
        description = "Detects access to sensitive file paths"
        category = "SD-03 · Data Exfiltration"
        severity = "CRITICAL"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $path1 = "/.ssh/" nocase
        $path2 = "/.aws/" nocase
        $path3 = "/.env" nocase
        $path4 = "CLAUDE.md" nocase
        $path5 = ".cursor/" nocase
        $path6 = "/.config/" nocase
        $path7 = "credentials" nocase

    condition:
        any of them
}

rule SD03_Network_Exfiltration
{
    meta:
        description = "Detects patterns that could lead to network data exfiltration"
        category = "SD-03 · Data Exfiltration"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $net1 = "requests.post(" nocase
        $net2 = "urllib.request.urlopen(" nocase
        $net3 = "httpx.post(" nocase
        $net4 = /http.*\/\/.*\.com/i
        $net5 = /curl.*http/i

    condition:
        any of them
}
