$api='VirusTotal_API_KEY'
foreach($hash in Get-Content 'Pass_The_Path_To_.CSV_FIle_That_Contains_Hashes')
{
    Write-Host "Adding : $hash"
    $body =@{resource=$hash;apikey=$api}
    $VT = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body
    $VT.Scans | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name | ForEach-Object {
	$Table += [PSCustomObject]@{ 'Engine' = $_; 'Detected' = $VT.Scans.$_.Detected; 'Version' = $VT.Scans.$_.Version; 'Updated' = $VT.Scans.$_.Update; 'Hash' = $Hash }
    }
    $Table |Export-Csv -path 'Output_.CSV_File_Path' -NoTypeInformation | Format-Table -AutoSize
    Write-Host "Hash: " $hash -ForegroundColor red -BackgroundColor white

    $Detected123  = Import-Csv -path 'Output_.CSV_File_Path' | Select-Object -Unique Detected,Hash
    $Detected123 | Format-Table -AutoSize
}
ForEach ($H in $Detected123)
{
    If($H.Detected -eq 'False')
    {
       # $CLEAN_HASH =  Add-Content  -Path .\Clean_Hash.csv -Value $H.Hash
       Write-Host("CLEAN")
       $Clean_Hash = Add-Content -Path .\Clean_Hash.csv -Value $H.Hash 
    }
    Else
    {
       # $MALICIOUS_HASH = Add-Content -Path .\Malicious_Hash.csv -Value $H.Hash 
       Write-Host("Malicious")
       $Malicious_Hash = Add-Content -Path .\Malicious_Hash.csv -Value $H.Hash 
    }
}

$CC_HASH = Import-Csv -Path .\Clean_Hash.csv -Header Hash | Select-Object -Unique * 
$MM_HASH = Import-Csv -Path .\Malicious_Hash.csv -Header Hash| Select-Object -Unique * 

#$C_Hash = $CC_HASH | Export-Csv -Path .\C_Hash.csv -NoTypeInformation | Format-Table -AutoSize
#$M_Hash = $MM_HASH | Export-Csv -Path .\M_Hash.csv -NoTypeInformation | Format-Table -AutoSize


$csv1 = Import-Csv -Path .\C_Hash.csv
$csv2 = Import-Csv -Path .\M_Hash.csv
 
$duplicates = Compare-Object $csv1 $csv2 -Property HASH -IncludeEqual -ExcludeDifferent -PassThru | Select-Object -ExpandProperty HASH
 
$csv1 | Where-Object { $_.HASH -notin $duplicates } | Export-Csv -Path .\C_Hash.csv -NoTypeInformation
 
#$csv2 | Where-Object { $_.$HASH -notin $duplicates } | Export-Csv -Path .\M_Hash.csv -NoTypeInformation

#Write-Host ("**************************Scan Completed*************************") -ForegroundColor Green
$wshell = New-Object -ComObject Wscript.Shell
$wshell.Popup("Scan Completed",0,"HASH",0x1)
