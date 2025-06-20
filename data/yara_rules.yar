rule Suspicious_File
{
    strings:
        $a = "malware"
        $b = "backdoor"
    condition:
        any of them
}