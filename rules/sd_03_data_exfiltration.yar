rule sd_03_data_exfiltration {
    meta:
        id = "SD-03"
        class = "Data Exfiltration"
        description = "Data exfiltration via environment, secrets, or context dump"
        severity = "HIGH"

    strings:
        $env_node = "process.env" nocase
        $env_perl = "$ENV{" nocase
        $env_python = "os.environ" nocase
        $aws_secret = "AWS_SECRET" nocase
        $gh_token = "GITHUB_TOKEN" nocase
        $api_key = /api[_-]?key/i
        $dotenv = /\.env\b/
        $secret_path = /\/etc\/(shadow|passwd)/
        $context_dump = "dump all" nocase

    condition:
        any of them
}
