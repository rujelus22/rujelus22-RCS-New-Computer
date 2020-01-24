Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' -Force -Recurse -Confirm:$false
Start-Sleep 1
Get-Process Explorer | Stop-Process