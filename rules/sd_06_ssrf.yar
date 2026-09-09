rule sd_06_ssrf {
    meta:
        id = "SD-06"
        class = "SSRF via tool parameters"
        description = "Server-Side Request Forgery via tool parameters"
        severity = "HIGH"

    strings:
        $localhost = "127.0.0.1" nocase
        $metadata_aws = "169.254.169.254"
        $metadata_gcp = "metadata.google.internal"
        $internal_url = /http:\/\/localhost/i
        $file_proto = "file://" nocase
        $internal_net = /10\.\d+\.\d+\.\d+/

    condition:
        any of them
}
