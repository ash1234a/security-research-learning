rule EICAR_Smoke_Test {
    meta:
        purpose = "pipeline-smoke-test"
        source = "eicar"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar at 0 and filesize < 128
}
