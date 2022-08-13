# VirusTotal_Powershell
Powershell script to analyze hashes on virustotal

Hash_Scan.ps1 scnas single hash value at a time.

Multi_Hash_Scan.ps1 powershell script scans for multiple hash values from a .csv file and then add them to new csv files which is clean and malicious.csv file respectively.
Finally it check for any duplicates in newly created clean.csv and malicious.csv and then create new files with no duplicates for clean and malicious hashs
