Push-Location 'C:\Users\danso\OneDrive\NanoServer'
Import-Module .\NanoServerImageGenerator.psm1
$parms.Clear()
$parms = @{'BasePath'='D:\NanoServer';
            'TargetPath'='D:\NanoServer\DansNanoServer.vhdx';
            'Compute'=$true;
            'Clustering'=$true;
            'Containers'=$true;
            'Storage'=$true;
            'DeploymentType'='Guest';
            'Edition'='Standard';
            'AdministratorPassword'=("P@ssword" | ConvertTo-SecureString -AsPlainText -Force)
}

#New-NanoServerImage -MediaPath H:\ -BasePath $parms.BasePath -DeploymentType Guest -Edition Standard

New-NanoServerImage @parms

#$parms.AdministratorPassword