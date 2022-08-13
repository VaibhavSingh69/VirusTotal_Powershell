$Table=@()
$api='Your_Virustotal_API_Key'
$hash='Hash_That_You_Want_To_Scan'
$body =@{resource=$hash;apikey=$api}
$VT = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body
$VT.Scans | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name | ForEach-Object {
	$Table += [PSCustomObject]@{ 'Engine' = $_; 'Detected' = $VT.Scans.$_.Detected; 'Version' = $VT.Scans.$_.Version; 'Updated' = $VT.Scans.$_.Update; 'Hash' = $Hash }
}
$Table | Format-Table -AutoSize
Write-Host "Hash: " $hash -ForegroundColor red -BackgroundColor white
