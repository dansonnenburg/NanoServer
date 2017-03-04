Push-Location C:\NanoServer\NanoServerImageGenerator

Import-Module .\NanoServerImageGenerator.psm1

#New-NanoServerImage -MediaPath e:\ -BasePath C:\NanoServer

<#
New-NanoServerImage -BasePath C:\NanoServer -TargetPath C:\NanoServer\NanoPoC.vhdx `
-Compute Guest -Clustering Datacenter -Containers -Storage `
-DomainBlobPath C:\NanoServer\NanoServerPoC_Blob.txt `
-AdministratorPassword ('P@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force)
#>

New-NanoServerImage -BasePath C:\NanoServer -TargetPath C:\NanoServer\NanoPoC.vhdx `
-Compute Guest -Clustering Datacenter -Containers -Storage `
-AdministratorPassword ('P@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force)


copy C:\NanoServer\NanoPoC.vhdx "C:\Users\Public\Documents\Hyper-V\Virtual hard disks"

$VMName = "NanoServer"

New-VM -Name $VMName -Generation 2 -SwitchName Private -MemoryStartupBytes 512MB `
-VHDPath "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\NanoPoC.vhdx" #| Set-VM 

vmconnect.exe localhost $VMName
Start-VM -Name $VMName