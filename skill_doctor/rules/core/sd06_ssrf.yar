// SD-06: SSRF via Tool Parameters
// Detects patterns that could lead to Server-Side Request Forgery
// Adapted from Cisco Skill Scanner (Apache 2.0) and NVIDIA SkillSpector (MIT)

rule SD06_URL_Parameter_Injection
{
    meta:
        description = "Detects URL parameter injection in tool descriptions"
        category = "SD-06 · SSRF via Tool Parameters"
        severity = "HIGH"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $url1 = /parameter.*url.*user.*input/i
        $url2 = /tool.*fetch.*http/i
        $url3 = /callback.*url/i
        $url4 = /webhook.*url/i
        $url5 = /endpoint.*http/i

    condition:
        any of them
}

rule SD06_Internal_Access
{
    meta:
        description = "Detects attempts to access internal infrastructure"
        category = "SD-06 · SSRF via Tool Parameters"
        severity = "CRITICAL"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $internal1 = "http://localhost" nocase
        $internal2 = "http://127.0.0.1" nocase
        $internal3 = "http://169.254.169.254" nocase  // AWS metadata
        $internal4 = "http://metadata.google.internal" nocase  // GCP metadata
        $internal5 = "http://192.168." nocase  // Private network

    condition:
        any of them
}
