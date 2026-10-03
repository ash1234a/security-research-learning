rule EICAR_Smoke_Test {
    meta:
        purpose = "pipeline-smoke-test"
        source = "eicar"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar at 0 and filesize <= 128
}
