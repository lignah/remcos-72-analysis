rule Remcos_73b8f80_SETTINGS
{
    meta:
        sha256 = "73b8f80db93983c804bb8d8b2eb7beb1c11b2adb3564697ac3c5f340f502d578"
        family = "Remcos"
    strings:
        $a1 = "Remcos Agent initialized" ascii
        $a2 = "Remcos restarted by watchdog" ascii
        $a3 = "Watchdog module activated" ascii
        $b1 = "SETTINGS" ascii
        $b2 = "license_code.txt" ascii
        $b3 = "pro.ip-api.com" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB
        and 2 of ($a*) and 2 of ($b*)
}