rule Demo_Suspicious_String
{
    strings:
        $a = "malware"
        $b = "attack"
    condition:
        any of them
}
