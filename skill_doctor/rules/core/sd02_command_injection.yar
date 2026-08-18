// SD-02: Command Injection via Companion Scripts
// Detects dangerous Python patterns that could lead to command injection
// Adapted from Cisco Skill Scanner (Apache 2.0) and NVIDIA SkillSpector (MIT)

rule SD02_Subprocess_Unsanitized
{
    meta:
        description = "Detects subprocess calls with potentially unsanitized input"
        category = "SD-02 · Command Injection"
        severity = "CRITICAL"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $subprocess1 = "subprocess.run(" nocase
        $subprocess2 = "subprocess.call(" nocase
        $subprocess3 = "subprocess.Popen(" nocase
        $subprocess4 = "os.system(" nocase
        $subprocess5 = "os.popen(" nocase

    condition:
        any of them
}

rule SD02_Dangerous_Functions
{
    meta:
        description = "Detects dangerous Python functions (eval, exec, compile)"
        category = "SD-02 · Command Injection"
        severity = "CRITICAL"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $danger1 = "eval(" nocase
        $danger2 = "exec(" nocase
        $danger3 = "compile(" nocase
        $danger4 = "__import__(" nocase

    condition:
        any of them
}

rule SD02_Pickle_Unsafe
{
    meta:
        description = "Detects unsafe pickle deserialization"
        category = "SD-02 · Command Injection"
        severity = "CRITICAL"
        author = "Kalaris Labs (adapted from Cisco/NVIDIA)"

    strings:
        $pickle1 = "pickle.loads(" nocase
        $pickle2 = "pickle.load(" nocase
        $pickle3 = "cPickle.loads(" nocase

    condition:
        any of them
}
