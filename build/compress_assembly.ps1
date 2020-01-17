$wd = pwd
$tdll = [System.IO.File]::ReadAllBytes($wd.Path + "\..\LogitackerTest\bin\Release\LogitackerTest.dll")


$zipos = New-Object System.IO.MemoryStream
#$zipstream = [System.IO.Compression.GZipStream]::new($zipos, [System.IO.Compression.CompressionMode]::Compress)
$zipstream = New-Object System.IO.Compression.GZipStream -ArgumentList ($zipos, [System.IO.Compression.CompressionMode]::Compress)
$zipstream.Write($tdll, 0, $tdll.Length)
$zipstream.Close()

# Readback zipped data
$zippedbytes = $zipos.ToArray()
$lenzipped = $zippedbytes.Length
"Script length zipped $lenzipped"

# convert to base64
$scriptb64 = [System.Convert]::ToBase64String($zippedbytes)
$lenb64 = $scriptb64.Length
"Zipped script length base64 $lenb64"
#$scriptb64



$scriptb64 | Out-File -Encoding ascii compressed.b64