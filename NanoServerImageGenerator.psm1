Set-StrictMode -version 3
$ErrorActionPreference = "Stop"

$Script:LogFile = Join-Path -Path $Env:TEMP -ChildPath "NanoServerImageGenerator.log"
$Script:DismLogFile = Join-Path -Path $Env:TEMP -ChildPath "NanoServerImageGenerator (DISM).log"

$Script:VSDebuggerBinariesPath = Join-Path -Path ${Env:CommonProgramFiles(x86)} -ChildPath "Microsoft Shared\Phone Tools\14.0\Debugger\target\x64"
$Script:VSRedistOnecorePath = Join-Path -Path ${Env:ProgramFiles(x86)} -ChildPath "Microsoft Visual Studio 14.0\VC\redist\onecore"
$Script:VSCRTReleaseBinariesPath = Join-Path -Path $Script:VSRedistOnecorePath -ChildPath "x64\Microsoft.VC140.CRT"
$Script:VSCRTDebugBinariesPath = Join-Path -Path $Script:VSRedistOnecorePath -ChildPath "debug_nonredist\x64\Microsoft.VC140.DebugCRT"
$Script:VSUCRTBinariesPath = Join-Path -Path ${Env:ProgramFiles(x86)} -ChildPath "Windows Kits\10\bin\x64\ucrt"

### -----------------------------------
### Constants
### -----------------------------------

$IMAGE_NAME = "NanoServer.wim"
$IMAGE_CONVERTER = "Convert-WindowsImage.ps1"

$KERNEL_DEBUG_KEY_FILE = "KernelDebugKey.txt"

$BCD_TEMPLATE_PCAT_ENTRY = "``{a1943bbc-ea85-487c-97c7-c9ede908a38a``}"
$BCD_TEMPLATE_EFI_ENTRY = "``{b012b84d-c47c-4ed5-b722-c0c42163e569``}"

$LEVEL_WARNING = "WARNING"
$LEVEL_VERBOSE = "VERBOSE"
$LEVEL_OUTPUT = "OUTPUT"
$LEVEL_NONE = "NONE"

$DT_HOST = "Host"
$DT_GUEST = "Guest"

$Script:Editions = @{
    "Standard" = 1
    "Datacenter" = 2
}

$PACK_STORAGE = "Microsoft-NanoServer-Storage-Package"
$PACK_COMPUTE = "Microsoft-NanoServer-Compute-Package"
$PACK_DEFENDER = "Microsoft-NanoServer-Defender-Package"
$PACK_CLUSTERING = "Microsoft-NanoServer-FailoverCluster-Package"
$PACK_OEM_DRIVERS = "Microsoft-NanoServer-OEM-Drivers-Package"
$PACK_GUEST_DRIVERS = "Microsoft-NanoServer-Guest-Package"
$PACK_CONTAINERS = "Microsoft-NanoServer-Containers-Package"
$PACK_RAMDISK = "Microsoft-NanoServer-BootFromWim-Package"
$PACK_HOST = "Microsoft-NanoServer-Host-Package"

### -----------------------------------
### Strings
### -----------------------------------

Data Strings
{
# culture="en-US"
ConvertFrom-StringData @'
    # "Administrator" refers to the Windows user account.
    ERR_USER_MUST_BE_ADMINISTRATOR = This script must be run as Administrator.
    
    # The strings after the dashes are not translatable.
    ERR_INCLUDE_DOMAIN_NAME_OR_DOMAIN_BLOB_PATH = Include either -DomainName or -DomainBlobPath, not both.
    ERR_INCLUDE_COMPUTER_NAME_OR_DOMAIN_BLOB_PATH = Include either -ComputerName or -DomainBlobPath, not both.
    ERR_DOMAIN_NAME_NO_COMPUTER_NAME = -DomainName was included, but not -ComputerName.
    ERR_EMS_PORT_WITH_NO_EMS = -EMSPort was included, but not -EnableEMS.
    ERR_DEBUG_AND_EMS_PORTS_EQUAL = Both the kernel debugging port and the EMS port cannot be the same.
    ERR_REUSE_NODE_WITHOUT_JOIN = -ReuseDomainJoin was specified without -DomainName nor -DomainBlobPath.
    ERR_KDNET_KEY_NOT_PRODUCED = Unable to create KDNET key automatically, please provide one.
    ERR_NO_INTERFACE_SPECIFIED = When changing IP configuration, -InterfaceNameOrIndex needs to be specified.
    ERR_RAMDISK_FOR_WIM_ONLY = Only WIM images are supported for RAMDisk boot.
    ERR_INCLUDE_OEM_WITH_DT_GUEST = Do not include -OEMDrivers ('{0}') when -DeploymentType is {1}.
    ERR_IMAGE_WAS_NOT_PRODUCED = The requested image could not be created. Please consult the command output for additional information.
    ERR_REUSE_DOMAIN_NAME = The domain name might have been already used. You might need to rerun with -ReuseDomainNode.
    ERR_MSVS_REQUIRED = You have to install Microsoft Visual Studio 2015 Update 1 or higher in order to use -Development. You will also need to enable 'Common Tools for Visual C++' and 'Tools and Windows 10 SDK'.
    ERR_PACKAGE_NOT_APPLICABLE = Package '{0}' is not applicable to the selected edition.
    ERR_PASSWORD_EMPTY = Administrator password cannot be empty.

    # {0} is a number.
    ERR_EXTERNAL_CMD = Failed with {0}.

    # For the next block of messages, the strings between single quotes are not translatable.
    ERR_DIRECTORY_DOES_NOT_EXIST_IN_MEDIA_DIRECTORY = The '{0}' directory does not exist in the specified media path.
    # {2} is a path.
    ERR_DIRECTORY_DOES_NOT_EXIST_IN_DIRECTORY = The '{0}' directory does not exist in the '{1}' directory ('{2}').
    ERR_BASE_DIRECTORY_DOES_NOT_EXIST = The specified base directory does not exist.
    ERR_DIRECTORY_DOES_NOT_EXIST_IN_BASE_DIRECTORY = The '{0}' directory does not exist in the specified base directory.
    ERR_IMAGE_DOES_NOT_EXIST = The '{0}' image does not exist in the 'NanoServer' directory.
    ERR_IMAGE_DOES_NOT_EXIST_IN_BASE_DIRECTORY = The '{0}' image does not exist in the specified base directory.
    ERR_IMAGE_CONVERTER_SCRIPT_DOES_NOT_EXIST = The image converter script ('{0}') does not exist in the directory where this script is located.
    ERR_PACKAGE_DOES_NOT_EXIST = Package '{0}' does not exist.
    ERR_LANGUAGE_PACKAGE_DOES_NOT_EXIST = Language package '{0}' does not exist.
    ERR_ONE_OR_MORE_PACKAGES_DO_NOT_EXIST = One or more packages do not exist.
    ERR_DOMAIN_BLOB_DOES_NOT_EXIST = The specified domain blob does not exist.
    ERR_DRIVERS_DIRECTORY_DOES_NOT_EXIST = The specified drivers directory does not exist ('{0}').
    ERR_SPECIFIED_IMAGE_DOES_NOT_EXIST = The specified VHD(X)/WIM image does not exist.
    ERR_ONLY_ONE_PATH_PERMITTED = MediaPath and BasePath specified, but only one path expected.
    ERR_COPY_FILES_DOES_NOT_EXIST = CopyFiles specified but does not exist.
    ERR_MEDIA_PATH_WAS_NOT_SPECIFIED = MediaPath has not been specified. You need to run New-NanoServerImage with -MediaPath first.
    ERR_UNATTEND_TEMPLATE_DOES_NOT_EXIST = The specified Unattend file does not exist.
    
    # New-NanoImage cannot be translated.
    LOG_HEADER = {0} Cmdlet Started

    # {0} is a file path.
    MSG_DONE = Done. The log is at: {0}
    # {0} is a file path.
    MSG_TERMINATING_DUE_TO_ERROR = Terminating due to an error. See log file at: {0}

    MSG_COMPUTING_PATHS = Computing paths...
    MSG_CHECKING_PATHS = Checking paths...
    MSG_CREATING_PATHS = Creating paths...

    MSG_COPYING_FILES = Copying files...
    MSG_SKIPPING_FILE_COPY = Skipping file copy.
    
    MSG_CONVERTING_IMAGE = Converting image...

    MSG_MOUNTING_IMAGE = Mounting image...

    MSG_COPYING_FILES_TO_IMAGE = Copying files to the image...
    MSG_SKIPPING_COPYING_FILES_TO_IMAGE = Skipping copying of files to the image.
    
    MSG_ADDING_DEBUGGER = Adding debugger...
    
    MSG_ADDING_PACKAGES = Adding packages...
    # {0} is a file name.
    MSG_ADDING_PACKAGE = Adding package '{0}'...
    # {0} is a file name.
    MSG_ADDING_LANGUAGE_PACKAGE = Adding language package for '{0}'...
    MSG_SKIPPING_PACKAGE_ADDITION = Skipping package addition.

    MSG_ADDING_DRIVERS = Adding drivers...
    MSG_SKIPPING_DRIVER_ADDITION = Skipping driver addition.

    # The file name is not translatable.
    MSG_ADDING_UNATTEND = Adding Unattend.xml...
    MSG_COLLECTING_DOMAIN_BLOB = Collecting domain provisioning blob...
    MSG_JOINING_DOMAIN = Joining domain...
    
    MSG_SETUPCOMPLETE_CHANGES_FOR_BOOTED_MEDIA = If the target image has been already booted, some of the requested changes will not be applied ({0}).

    MSG_ENABLING_DEBUG = Enabling Debug and BootDebug...
    # {0} is a file path.
    MSG_KERNEL_DEBUG_KEY_FILE = Find the kernel debugging key at: {0}

    MSG_ENABLING_EMS = Enabling EMS and BootEMS...
    
    MSG_ENABLING_TESTSIGNING = Enabling TestSigning...

    MSG_DISMOUNTING_IMAGE = Dismounting image...

    MSG_TARGET_IMAGE = Target image: '{0}'
    
    MSG_START_DEBUGGER = Before starting the debugging session, start the debugger server in remote PS session using {0}.
'@
}

# Import localized strings
Import-LocalizedData Strings -FileName NanoServerImageGenerator.Strings.psd1 -ErrorAction SilentlyContinue

### -----------------------------------
### Get-NanoServerPackage Cmdlet
### -----------------------------------

Function Get-NanoServerPackage
{
    [CmdletBinding()]
    Param
    (
        # Location of the source media.
        [String]$MediaPath,
        # Where to place the copy of the source media.
        [String]$BasePath
    )

    Process
    {
        Write-LogHeader
    
        $Script:NewImage = $True

        # Tracking (used to handle Ctrl-C gracefully)
        $HasWorkFinished = $False

        # Phase 0
        try
        {
            if ($MediaPath -and $BasePath)
            {
                Throw $Strings.ERR_ONLY_ONE_PATH_PERMITTED
            }
            
            Initialize-PathValues `
                -BasePath $BasePath `
                -MediaPath $MediaPath
            Test-Paths

            $Dirs = @()
            if ($Script:HasMediaPath)
            {
                $Dirs += $Script:PackagesPath
                $Dirs += $Script:LanguagePackagesPath
            }
            else
            {
                $Dirs += $Script:BasePackagesPath
                $Dirs += $Script:BaseLanguagePackagesPath
            }
            
            $Packages = $Dirs | ForEach-Object {
                (Get-ChildItem -Path $_ -Filter "*.cab").Name
            } | % { Get-PackageName $_ } | Sort-Object | Get-Unique
            
            $HasWorkFinished = $True
            
            return $Packages
        }
        catch
        {
            Write-Log $LEVEL_WARNING ("{0}`n{1}" -f $_, $_.ScriptStackTrace) -NoOutput
            Write-Log $LEVEL_WARNING ($Strings.MSG_TERMINATING_DUE_TO_ERROR -f $Script:LogFile) $True
            
            Throw
        }
    }
}

### -----------------------------------
### New-NanoServerImage Cmdlet
### -----------------------------------

Function New-NanoServerImage
{
    [CmdletBinding()]
    Param
    (
        # Deployment type for the produced image.
        [Parameter(Mandatory = $True, Position=0)]
        [ValidateSet("Host", "Guest")]
        [String]$DeploymentType,
        
        # Edition of the produced image.
        [Parameter(Mandatory = $True, Position=1)]
        [ValidateSet("Standard", "Datacenter")]
        [String]$Edition,
    
        # Location of the source media.
        [Parameter()]
        [String]$MediaPath,
        # Where to place the copy of the source media.
        [Parameter()]
        [String]$BasePath,
        # Path to the produced image.
        [Parameter(Mandatory = $True)]
        [ValidatePattern('\.(vhdx?|wim)$')]
        [String]$TargetPath,
        
        # Output image maximum size.
        [ValidateRange(512MB, 64TB)]
        [UInt64]$MaxSize = 4GB,
        
        # Include the Storage package.
        [Switch]$Storage,
        # Include the Compute (Hyper-V) package.
        [Switch]$Compute,
        # Include the Windows Defender package.
        [Switch]$Defender,
        # Include the Failover Clustering package.
        [Switch]$Clustering,
        # Include the OEM Drivers package.
        [Switch]$OEMDrivers,
        # Include the Containers package.
        [Switch]$Containers,

        # Include the following packages from media.
        [String[]]$Packages,
        # Include the following servicing packages.
        [String[]]$ServicingPackages,
        
        # Name to give to the target computer.
        [ValidateLength(1, 15)]
        [String]$ComputerName,
        # Password for the administrator account of the target computer.
        [Parameter(Mandatory = $True)]
        [SecureString]$AdministratorPassword,
        # Unattend template path
        [String]$UnattendPath,

        # Name of the domain.
        [ValidateNotNullOrEmpty()]
        [String]$DomainName,
        # Location of the domain blob.
        [ValidateNotNullOrEmpty()]
        [String]$DomainBlobPath,
        # Force reusing a node when joining a domain.
        [Switch]$ReuseDomainNode,

        # Location of additional drivers to include.
        [ValidateNotNullOrEmpty()]
        [String]$DriversPath,
        
        # Configure this interface statically.
        [ValidateNotNullOrEmpty()]
        [String]$InterfaceNameOrIndex,
        
        # Set statically IPv6 address.
        [ValidateNotNullOrEmpty()]
        [String]$Ipv6Address,
        
        # Set statically IPv6 DNS servers.
        [ValidateNotNullOrEmpty()]
        [String[]]$Ipv6Dns,
        
        # Set statically IPv4 address.
        [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
        [String]$Ipv4Address,
        
        # Set statically IPv4 subnet mask.
        [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
        [String]$Ipv4SubnetMask,
        
        # Set statically IPv4 gateway.
        [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
        [String]$Ipv4Gateway,
        
        # Set statically IPv4 DNS servers.
        [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
        [String[]]$Ipv4Dns,

        # Enable Debug and BootDebug in the target BCD.
        [ValidateSet("Serial", "Net", "1394", "USB")]
        [String]$DebugMethod,

        # Enable EMS and BootEMS in the target BCD.
        [Switch]$EnableEMS,
        # Port to use for EMS.
        [Parameter()]
        [Byte]$EMSPort = 1,
        # Baud rate to use for EMS.
        [Parameter()]
        [UInt32]$EMSBaudRate = 115200,

        # Open port 5985 for inbound TCP connections for WinRM from any location,
        # not just the domain network and the local subnet.
        [Switch]$EnableRemoteManagementPort,
        
        # Will be copied into the root of the image.
        [String[]]$CopyFiles,
        
        # List of commands to be executed after the setup completes.
        [String[]]$SetupCompleteCommands,
        
        # Enable RAMDisk boot.
        [Switch]$RamdiskBoot,
        
        # Enable for development scenarios.
        [Switch]$Development
    )
    
    DynamicParam {
        $DynamicParameters = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        
        if (-not (Test-Path Variable:\DebugMethod))
        {
            $DebugMethod = $null
        }
        
        switch ($DebugMethod)
        {
            "Serial" {
                # Debug Port
                $DebugCOMPort = New-DynamicParameter "DebugCOMPort" Byte 2
                $DynamicParameters.Add($DebugCOMPort.Name, $DebugCOMPort)

                # Debug Baud Rate
                $DebugBaudRate = New-DynamicParameter "DebugBaudRate" UInt32 115200
                $DynamicParameters.Add($DebugBaudRate.Name, $DebugBaudRate)
            }

            "Net" {
                # Remote IP
                $DebugRemoteIP = New-DynamicParameter "DebugRemoteIP" String -Mandatory -NotNull
                $DynamicParameters.Add($DebugRemoteIP.Name, $DebugRemoteIP)

                # Remote Port
                $DebugPort = New-DynamicParameter "DebugPort" UInt16 -Mandatory
                $DynamicParameters.Add($DebugPort.Name, $DebugPort)

                # Key
                $DebugKey = New-DynamicParameter "DebugKey" String -NotNull
                $DynamicParameters.Add($DebugKey.Name, $DebugKey)
            }

            "1394" {
                # Channel
                $DebugChannel = New-DynamicParameter "DebugChannel" UInt16 -Mandatory
                $DynamicParameters.Add($DebugChannel.Name, $DebugChannel)
            }

            "USB" {
                # Target Name
                $DebugTargetName = New-DynamicParameter "DebugTargetName" String -Mandatory -NotNull
                $DynamicParameters.Add($DebugTargetName.Name, $DebugTargetName)
            }
        }

        return $DynamicParameters
    }

    Process
    {
        Write-LogHeader
    
        $Script:NewImage = $True

        # Checks
        Verify-UserIsAdministrator
        if ($Development)
        {
            Verify-MSVS14U1Installed
        }
        
        if ($DomainName -and $DomainBlobPath)
        {
            Throw $Strings.ERR_INCLUDE_DOMAIN_NAME_OR_DOMAIN_BLOB_PATH
        }
        if ($DomainBlobPath -and $ComputerName)
        {
            Throw $Strings.ERR_INCLUDE_COMPUTER_NAME_OR_DOMAIN_BLOB_PATH
        }
        if ($DomainName -and !$ComputerName)
        {
            Throw $Strings.ERR_DOMAIN_NAME_NO_COMPUTER_NAME
        }
        if (!$EnableEMS -and $PSBoundParameters.ContainsKey("EMSPort"))
        {
            Throw $Strings.ERR_EMS_PORT_WITH_NO_EMS
        }
        if ($OEMDrivers -and $DeploymentType -eq $DT_GUEST)
        {
            Throw ($Strings.ERR_INCLUDE_OEM_WITH_DT_GUEST -f $PACK_OEM_DRIVERS, $DT_GUEST)
        }
        if (($DebugMethod -eq "Serial") -and $EnableEMS -and ($DebugCOMPort.Value -eq $EMSPort))
        {
            Throw $Strings.ERR_DEBUG_AND_EMS_PORTS_EQUAL
        }
        if ($ReuseDomainNode -and (!$DomainName -and !$DomainBlobPath))
        {
            Throw $Strings.ERR_REUSE_NODE_WITHOUT_JOIN
        }
        if (($Ipv4Address -or $Ipv6Address -or $Ipv4Dns -or $Ipv6Dns) -and -not $InterfaceNameOrIndex)
        {
            Throw $Strings.ERR_NO_INTERFACE_SPECIFIED
        }
        if ($RamdiskBoot -and -not ($TargetPath -like "*.wim"))
        {
            Throw $Strings.ERR_RAMDISK_FOR_WIM_ONLY
        }
        if ($AdministratorPassword -and -not (ConvertTo-String $AdministratorPassword))
        {
            Throw $Strings.ERR_PASSWORD_EMPTY
        }
        
        # Tracking (used to handle Ctrl-C gracefully)
        $HasWorkFinished = $False
        $HasMountedImage = $False
        $HasMountedEsp = $False
        $SystemPartitionGuid = $Null

        # Phase 0
        $Packages = [String[]](Initialize-Packages `
            -Packages $Packages `
            -Storage:$Storage `
            -Compute:$Compute `
            -Defender:$Defender `
            -Clustering:$Clustering `
            -OEMDrivers:$OEMDrivers `
            -GuestDrivers:($DeploymentType -eq $DT_GUEST) `
            -Containers:$Containers `
            -RamdiskBoot:$RamdiskBoot `
            -Host:($DeploymentType -eq $DT_HOST))
            
        try
        {
            Initialize-PathValues `
                $BasePath `
                $TargetPath `
                $DriversPath `
                $DomainBlobPath `
                $Packages `
                -MediaPath $MediaPath `
                -MaxSize $MaxSize `
                -CopyFiles $CopyFiles

            Initialize-Paths
            Test-Paths $Packages $ServicingPackages $UnattendPath

            # Phase 1
            Copy-Files
            
            Convert-Image $Edition
            if ($RamdiskBoot)
            {
                Enable-RamdiskBoot
            }
            
            # Phase 2
            Mount-Image
            $HasMountedImage = $True
            
            if ($Development)
            {
                Add-Debugger
            }
            
            Add-Files
            Add-Packages $Packages $ServicingPackages
            Add-Drivers $Development

            # Phase 3
            Add-ServicingDescriptor $ComputerName $AdministratorPassword $UnattendPath
            Join-Domain $ComputerName $DomainName $ReuseDomainNode

            # Phase 4
            if ($EnableRemoteManagementPort -or $InterfaceNameOrIndex -or $SetupCompleteCommands -or $Development)
            {
                Write-SetupComplete `
                    $EnableRemoteManagementPort `
                    $InterfaceNameOrIndex `
                    $Ipv6Address `
                    $Ipv6Dns `
                    $Ipv4Address `
                    $Ipv4SubnetMask `
                    $Ipv4Gateway `
                    $Ipv4Dns `
                    $SetupCompleteCommands `
                    $Development
            }
            
            if ($DebugMethod -or $EnableEMS -or $Development)
            {
                switch ($Script:ImageFormat)
                {
                    "vhdx" 
                    {
                        $SystemPartitionGuid = Mount-AsBasicData
                        $HasMountedEsp = $True
                        $BCDPath = "$Script:TargetMountEspPath\efi\microsoft\boot\bcd"
                    }
                    
                    "vhd"
                    {
                        $BCDPath = "$Script:TargetMountPath\boot\bcd"
                    }
                    
                    default 
                    {
                        $BCDPath = $Null
                    }
                }
                
                $BCDTemplatePath = "$Script:TargetMountPath\windows\system32\config\bcd-template"
                
                if ($DebugMethod)
                {
                    Enable-Debug $BCDPath $BCDTemplatePath

                    switch ($DebugMethod)
                    {
                        "Serial" { Enable-DebugSerial $BCDPath $BCDTemplatePath $DebugCOMPort.Value $DebugBaudRate.Value }
                        "Net" { Enable-DebugNet $BCDPath $BCDTemplatePath $DebugRemoteIP.Value $DebugPort.Value $DebugKey.Value }
                        "1394" { Enable-DebugFirewire $BCDPath $BCDTemplatePath $DebugChannel.Value }
                        "USB" { Enable-DebugUSB $BCDPath $BCDTemplatePath $DebugTargetName.Value }
                    }
                }
                if ($EnableEMS)
                {
                    Enable-EMS $BCDPath $BCDTemplatePath $EMSPort $EMSBaudRate
                }
                if ($Development)
                {
                    Enable-TestSigning $BCDPath $BCDTemplatePath
                }
            }

            if ($HasMountedEsp)
            {
                Dismount-AsSystemPartition $SystemPartitionGuid
                $HasMountedEsp = $False
            }
        
            if ($HasMountedImage)
            {
                Dismount-Image
                $HasMountedImage = $False
            }
            
            Write-Log $LEVEL_OUTPUT ($Strings.MSG_DONE -f $LogFile) $True

            $HasWorkFinished = $True
        }
        catch
        {
            Write-Log $LEVEL_WARNING ("{0}`n{1}" -f $_, $_.ScriptStackTrace) -NoOutput
            Write-Log $LEVEL_WARNING ($Strings.MSG_TERMINATING_DUE_TO_ERROR -f $Script:LogFile) $True
            
            if ($HasMountedEsp)
            {
                Dismount-AsSystemPartition $SystemPartitionGuid
                $HasMountedEsp = $False
            }
        
            if ($HasMountedImage)
            {
                Dismount-Image -Discard
                $HasMountedImage = $False
            }
            
            Throw
        }
        finally
        {
            if ($HasWorkFinished)
            {
                # All good.
                Remove-Item -Recurse -Path $Script:TargetTempPath
            }
        }
    }
}

### -----------------------------------
### Edit-NanoServerImage Cmdlet
### -----------------------------------

Function Edit-NanoServerImage
{
    [CmdletBinding()]
    Param
    (
        # Where to place the copy of the source media.
        [String]$BasePath,
        # Location of the image to use.
        [Parameter(Mandatory = $True)]
        [ValidatePattern('\.(vhdx?|wim)$')]
        [String]$TargetPath,

        # Include the Storage package.
        [Switch]$Storage,
        # Include the Compute (Hyper-V) package.
        [Switch]$Compute,
        # Include the Windows Defender package.
        [Switch]$Defender,
        # Include the Failover Clustering package.
        [Switch]$Clustering,
        # Include the OEM Drivers package.
        [Switch]$OEMDrivers,
        # Include the Containers package.
        [Switch]$Containers,

        # Include the following packages from media.
        [String[]]$Packages,
        # Include the following servicing packages.
        [String[]]$ServicingPackages,
        
        # Name to give to the target computer.
        [ValidateLength(1, 15)]
        [String]$ComputerName,
        # Password for the administrator account of the target computer.
        [SecureString]$AdministratorPassword,
        # Unattend template path
        [String]$UnattendPath,

        # Name of the domain.
        [ValidateNotNullOrEmpty()]
        [String]$DomainName,
        # Location of the domain blob.
        [ValidateNotNullOrEmpty()]
        [String]$DomainBlobPath,
        # Force reusing a node when joining a domain.
        [Switch]$ReuseDomainNode,

        # Location of additional drivers to include.
        [ValidateNotNullOrEmpty()]
        [String]$DriversPath,
        
        # Configure this interface statically.
        [ValidateNotNullOrEmpty()]
        [String]$InterfaceNameOrIndex,
        
        # Set statically IPv6 address.
        [ValidateNotNullOrEmpty()]
        [String]$Ipv6Address,
        
        # Set statically IPv6 DNS servers.
        [ValidateNotNullOrEmpty()]
        [String[]]$Ipv6Dns,
        
        # Set statically IPv4 address.
        [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
        [String]$Ipv4Address,
        
        # Set statically IPv4 subnet mask.
        [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
        [String]$Ipv4SubnetMask,
        
        # Set statically IPv4 gateway.
        [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
        [String]$Ipv4Gateway,
        
        # Set statically IPv4 DNS servers.
        [ValidatePattern('^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')]
        [String[]]$Ipv4Dns,

        # Enable Debug and BootDebug in the target BCD.
        [ValidateSet("Serial", "Net", "1394", "USB")]
        [String]$DebugMethod,

        # Enable EMS and BootEMS in the target BCD.
        [Switch]$EnableEMS,
        # Port to use for EMS.
        [Parameter()]
        [Byte]$EMSPort = 1,
        # Baud rate to use for EMS.
        [Parameter()]
        [UInt32]$EMSBaudRate = 115200,

        # Open port 5985 for inbound TCP connections for WinRM.
        [Switch]$EnableRemoteManagementPort,
        
        # Will be copied into the root of the image.
        [String[]]$CopyFiles,
        
        # List of commands to be executed after the setup completes.
        [String[]]$SetupCompleteCommands,

        # Enable RAMDisk boot.
        [Switch]$RamdiskBoot,
        
        # Enable for development scenarios.
        [Switch]$Development,

        # Override location of language packages.
        [String]$LangPackages,

        # Override location of neutral packages.
        [String]$NeutralPackages
    )

    DynamicParam {
        $DynamicParameters = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        
        if (-not (Test-Path Variable:\DebugMethod))
        {
            $DebugMethod = $null
        }

        switch ($DebugMethod)
        {
            "Serial" {
                # Debug Port
                $DebugCOMPort = New-DynamicParameter "DebugCOMPort" Byte 2
                $DynamicParameters.Add($DebugCOMPort.Name, $DebugCOMPort)

                # Debug Baud Rate
                $DebugBaudRate = New-DynamicParameter "DebugBaudRate" UInt32 115200
                $DynamicParameters.Add($DebugBaudRate.Name, $DebugBaudRate)
            }

            "Net" {
                # Remote IP
                $DebugRemoteIP = New-DynamicParameter "DebugRemoteIP" String -Mandatory -NotNull
                $DynamicParameters.Add($DebugRemoteIP.Name, $DebugRemoteIP)

                # Remote Port
                $DebugPort = New-DynamicParameter "DebugPort" UInt16 -Mandatory
                $DynamicParameters.Add($DebugPort.Name, $DebugPort)

                # Key
                $DebugKey = New-DynamicParameter "DebugKey" String -NotNull
                $DynamicParameters.Add($DebugKey.Name, $DebugKey)
            }

            "1394" {
                # Channel
                $DebugChannel = New-DynamicParameter "DebugChannel" UInt16 -Mandatory
                $DynamicParameters.Add($DebugChannel.Name, $DebugChannel)
            }

            "USB" {
                # Target Name
                $DebugTargetName = New-DynamicParameter "DebugTargetName" String -Mandatory -NotNull
                $DynamicParameters.Add($DebugTargetName.Name, $DebugTargetName)
            }
        }

        return $DynamicParameters
    }

    Process
    {
        Write-LogHeader
    
        $Script:NewImage = $False

        # Checks
        Verify-UserIsAdministrator
        if ($Development)
        {
            Verify-MSVS14U1Installed
        }
        
        if ($DomainName -and $DomainBlobPath)
        {
            Throw $Strings.ERR_INCLUDE_DOMAIN_NAME_OR_DOMAIN_BLOB_PATH
        }
        if ($DomainBlobPath -and $ComputerName)
        {
            Throw $Strings.ERR_INCLUDE_COMPUTER_NAME_OR_DOMAIN_BLOB_PATH
        }
        if ($DomainName -and !$ComputerName)
        {
            Throw $Strings.ERR_DOMAIN_NAME_NO_COMPUTER_NAME
        }
        if (!$EnableEMS -and $PSBoundParameters.ContainsKey("EMSPort"))
        {
            Throw $Strings.ERR_EMS_PORT_WITH_NO_EMS
        }
        if (($DebugMethod -eq "Serial") -and $EnableEMS -and ($DebugCOMPort.Value -eq $EMSPort))
        {
            Throw $Strings.ERR_DEBUG_AND_EMS_PORTS_EQUAL
        }
        if ($ReuseDomainNode -and (!$DomainName -and !$DomainBlobPath))
        {
            Throw $Strings.ERR_REUSE_NODE_WITHOUT_JOIN
        }
        if (($Ipv4Address -or $Ipv6Address -or $Ipv4Dns -or $Ipv6Dns) -and -not $InterfaceNameOrIndex)
        {
            Throw $Strings.ERR_NO_INTERFACE_SPECIFIED
        }
        if ($RamdiskBoot -and -not ($TargetPath -like "*.wim"))
        {
            Throw $Strings.ERR_RAMDISK_FOR_WIM_ONLY
        }
        if ($AdministratorPassword -and -not (ConvertTo-String $AdministratorPassword))
        {
            Throw $Strings.ERR_PASSWORD_EMPTY
        }
        
        # Tracking (used to handle Ctrl-C gracefully)
        $HasWorkFinished = $False
        $HasMountedImage = $False
        $HasMountedEsp = $False
        $SystemPartitionGuid = $null

        # Phase 0
        $Packages = [String[]](Initialize-Packages `
            -Packages $Packages `
            -Storage:$Storage `
            -Compute:$Compute `
            -Defender:$Defender `
            -Clustering:$Clustering `
            -OEMDrivers:$OEMDrivers `
            -Containers:$Containers `
            -RamdiskBoot:$RamdiskBoot)

        try
        {
            Initialize-PathValues `
                $BasePath `
                $TargetPath `
                $DriversPath `
                $DomainBlobPath `
                $Packages `
                -CopyFiles $CopyFiles

            Initialize-Paths
            Test-Paths $Packages $ServicingPackages $UnattendPath

            # Phase 1
            if ($RamdiskBoot)
            {
                Enable-RamdiskBoot
            }

            # Phase 2
            Mount-Image
            $HasMountedImage = $True
            
            if ($Development)
            {
                Add-Debugger
            }

            Add-Files
            Add-Packages $Packages $ServicingPackages
            Add-Drivers $Development

            # Phase 3
            Add-ServicingDescriptor $ComputerName $AdministratorPassword $UnattendPath
            Join-Domain $ComputerName $DomainName $ReuseDomainNode

            # Phase 4
            if ($EnableRemoteManagementPort -or $InterfaceNameOrIndex -or $SetupCompleteCommands -or $Development)
            {
                Write-SetupComplete `
                    $EnableRemoteManagementPort `
                    $InterfaceNameOrIndex `
                    $Ipv6Address `
                    $Ipv6Dns `
                    $Ipv4Address `
                    $Ipv4SubnetMask `
                    $Ipv4Gateway `
                    $Ipv4Dns `
                    $SetupCompleteCommands `
                    $Development
            }
            
            if ($DebugMethod -or $EnableEMS -or $Development)
            {
                switch ($Script:ImageFormat)
                {
                    "vhdx" 
                    {
                        $SystemPartitionGuid = Mount-AsBasicData
                        $HasMountedEsp = $True
                        $BCDPath = "$Script:TargetMountEspPath\efi\microsoft\boot\bcd"
                    }
                    
                    "vhd"
                    {
                        $BCDPath = "$Script:TargetMountPath\boot\bcd"
                    }
                    
                    default 
                    {
                        $BCDPath = $Null
                    }
                }
                
                $BCDTemplatePath = "$Script:TargetMountPath\windows\system32\config\bcd-template"
                
                if ($DebugMethod)
                {
                    Enable-Debug $BCDPath $BCDTemplatePath

                    switch ($DebugMethod)
                    {
                        "Serial" { Enable-DebugSerial $BCDPath $BCDTemplatePath $DebugCOMPort.Value $DebugBaudRate.Value }
                        "Net" { Enable-DebugNet $BCDPath $BCDTemplatePath $DebugRemoteIP.Value $DebugPort.Value $DebugKey.Value }
                        "1394" { Enable-DebugFirewire $BCDPath $BCDTemplatePath $DebugChannel.Value }
                        "USB" { Enable-DebugUSB $BCDPath $BCDTemplatePath $DebugTargetName.Value }
                    }
                }
                if ($EnableEMS)
                {
                    Enable-EMS $BCDPath $BCDTemplatePath $EMSPort $EMSBaudRate
                }
                if ($Development)
                {
                    Enable-TestSigning $BCDPath $BCDTemplatePath
                }
            }
            
            if ($HasMountedEsp)
            {
                Dismount-AsSystemPartition $SystemPartitionGuid
                $HasMountedEsp = $False
            }
        
            if ($HasMountedImage)
            {
                Dismount-Image
                $HasMountedImage = $False
            }
            
            Write-Log $LEVEL_OUTPUT ($Strings.MSG_DONE -f $LogFile) $True

            $HasWorkFinished = $True
        }
        catch
        {
            Write-Log $LEVEL_WARNING ("{0}`n{1}" -f $_, $_.ScriptStackTrace) -NoOutput
            Write-Log $LEVEL_WARNING ($Strings.MSG_TERMINATING_DUE_TO_ERROR -f $Script:LogFile) $True
            
            if ($HasMountedEsp)
            {
                Dismount-AsSystemPartition $SystemPartitionGuid
                $HasMountedEsp = $False
            }
        
            if ($HasMountedImage)
            {
                Dismount-Image -Discard
                $HasMountedImage = $False
            }

            Throw
        }
        finally
        {
            if ($HasWorkFinished)
            {
                # All good.
                Remove-Item -Recurse -Path $Script:TargetTempPath
            }
        }
    }
}

### -----------------------------------
### Phase 0
### -----------------------------------

Function Initialize-Packages(
    [String[]]$Packages,
    [Switch]$Storage,
    [Switch]$Compute,
    [Switch]$Defender,
    [Switch]$Clustering,
    [Switch]$OEMDrivers,
    [Switch]$GuestDrivers,
    [Switch]$Containers,
    [Switch]$RamdiskBoot,
    [Switch]$Host)
{
    $ResultPackages = @()
    
    $AdditionalPackages = @{
        $PACK_STORAGE = $Storage
        $PACK_COMPUTE = $Compute
        $PACK_DEFENDER = $Defender
        $PACK_CLUSTERING = $Clustering
        $PACK_OEM_DRIVERS = $OEMDrivers
        $PACK_GUEST_DRIVERS = $GuestDrivers
        $PACK_CONTAINERS = $Containers
        $PACK_RAMDISK = $RamdiskBoot
        $PACK_HOST = $Host
    }
    
    $AdditionalPackages.GetEnumerator() | ForEach-Object {
        if ($_.Value -and -not ($ResultPackages -Contains $_.Name))
        {
            $ResultPackages += $_.Name
        }
    }
    
    if ($Packages)
    {
        $Packages | ForEach-Object {
            if (-not ($ResultPackages -Contains $_))
            {
                $ResultPackages += $_
            }
        }
    }
    
    return $ResultPackages
}

Function Get-PackageFileName(
    [String]$PackageName,
    [String]$Language)
{
    $Ext = ".cab"

    if ($Language -and !$Script:Internal)
    {
        $Ext = "_$Language$Ext"
    }
    
    return $PackageName + $Ext
}

Function Get-PackageName(
    [String]$PackageFileName)
{
    return (($PackageFileName -Split "\\")[-1] -Split "_")[0] -Replace (".cab", "")
}

Function Initialize-PathValues(
    [String]$BasePath, 
    [String]$TargetPath, 
    [String]$DriversPath, 
    [String]$DomainBlobPath, 
    [String[]]$Packages,
    [String]$MediaPath, 
    [UInt64]$MaxSize,
    [String[]]$CopyFiles)
{
    Write-Verbose -Message $Strings.MSG_COMPUTING_PATHS
    
    # Compute the directory structure.
    # --------------------------------

    $Script:Internal = [Bool]$Env:NSIGTOOLS
    
    Get-PSDrive | Out-Null

    # Source
    $Script:HasMediaPath = [bool]$MediaPath
    if ($Script:HasMediaPath)
    {
        $Script:NanoPath = Join-Path -Path $MediaPath -ChildPath "NanoServer"
        $Script:PackagesPath = Join-Path -Path $NanoPath -ChildPath "Packages"
        $Language = (Get-ChildItem -Path $Script:PackagesPath -Directory).Name
        $Script:LanguagePackagesPath = Join-Path -Path $PackagesPath -ChildPath $Language
        $Script:SourcesPath = Join-Path -Path $MediaPath -ChildPath "sources"
    }

    # Base
    if (-not $BasePath)
    {
        $BasePath = Join-Path -Path $env:TEMP -ChildPath "NanoServerImageGenerator"
    }
    $Script:BasePath = $BasePath
    if (-not $Script:HasMediaPath -and -not (Test-Path $Script:BasePath) -and (-not $Script:Internal))
    {
        Throw $Strings.ERR_MEDIA_PATH_WAS_NOT_SPECIFIED
    }

    if ($Script:Internal)
    {
        $Script:BaseToolsPath = $Env:NSIGTOOLS
    }
    else
    {
        $Script:BaseToolsPath = Join-Path -Path $BasePath -ChildPath "Tools"
    }
    
    if (-not $Internal)
    {
        $Script:BasePackagesPath = Join-Path -Path $BasePath -ChildPath "Packages"

        if (-not $Script:HasMediaPath)
        {
            $Language = (Get-ChildItem -Path $Script:BasePackagesPath -Directory).Name
        }

        $Script:BaseLanguagePackagesPath = Join-Path -Path $Script:BasePackagesPath -ChildPath $Language
    }

    # Target
    if ($TargetPath)
    {
        $Script:TargetImageFilePath = $TargetPath
        $Script:TargetPath = [System.IO.Path]::GetDirectoryName($TargetPath)
        if (-not $Script:TargetPath)
        {
            $Script:TargetPath = "."
        }
        $Script:ImageFormat = [System.IO.Path]::GetExtension($TargetPath).Substring(1)
    }

    # Image size in bytes
    $Script:MaxSize = $MaxSize

    # Drivers
    $Script:DriversPath = $DriversPath

    # Domain
    $Script:DomainBlobPath = $DomainBlobPath

    # Compute the file paths.
    # -----------------------

    # Source
    if ($Script:Internal)
    {
        $Script:ImageConverterPath = $Null
    }
    else
    {
        $Script:ImageConverterPath = Join-Path -Path $PSScriptRoot -ChildPath $IMAGE_CONVERTER
    }
    
    if ($Script:HasMediaPath)
    {
        $Script:ImageFilePath = Join-Path -Path $Script:NanoPath -ChildPath $IMAGE_NAME;
    
        $Script:PackageFilePaths = @{}
        $Script:LanguagePackageFilePaths = @{}

        if ($Packages)
        {
            $Packages | ForEach-Object { 
                $Script:PackageFilePaths.Add($_, (Join-Path -Path $Script:PackagesPath -ChildPath (Get-PackageFileName $_))) 
                $Script:LanguagePackageFilePaths.Add($_, (Join-Path -Path $Script:LanguagePackagesPath -ChildPath (Get-PackageFileName $_ $Language)))
            }
        }
    }

    # Base
    $Script:BaseWimImageFilePath = Join-Path -Path $BasePath -ChildPath $IMAGE_NAME
    $Script:BaseDismFilePath = Join-Path -Path $Script:BaseToolsPath -ChildPath "dism.exe"

    $Script:BasePackageFilePaths = @{}
    $Script:BaseLanguagePackageFilePaths = @{}

    if ($Packages)
    {
        $Packages | ForEach-Object { 
            $Script:BasePackageFilePaths.Add($_, (Join-Path -Path $Script:BasePackagesPath -ChildPath (Get-PackageFileName $_))) 
            $Script:BaseLanguagePackageFilePaths.Add($_, (Join-Path -Path $Script:BaseLanguagePackagesPath -ChildPath (Get-PackageFileName $_ $Language)))
        }
    }

    if ($TargetPath)
    {
        $Script:BaseImageFilePath = Join-Path -Path $BasePath -ChildPath ((Split-Path -Path $BasePath -Leaf) + "." + $Script:ImageFormat)
    }

    # Target
    $Script:TargetTempPath = Join-Path -Path $BasePath -ChildPath "Temp"
    $Script:TargetMountPath = Join-Path -Path $Script:TargetTempPath -ChildPath ("w{0}" -f (Get-Random))
    $Script:TargetMountEspPath = Join-Path -Path $Script:TargetTempPath -ChildPath ("s{0}" -f (Get-Random))
    $Script:TargetUnattendFilePath = Join-Path -Path $Script:TargetTempPath -ChildPath "Unattend.xml"
    $Script:TargetDomainBlobPath = Join-Path -Path $Script:TargetTempPath -ChildPath "djoin.blob"
    $Script:TargetSetupCompleteFilePath = Join-Path -Path $Script:TargetTempPath -ChildPath "SetupComplete.cmd"
    
    if ($TargetPath)
    {
        $Script:TargetDebuggingKeyFilePath = Join-Path -Path $Script:TargetPath -ChildPath $KERNEL_DEBUG_KEY_FILE
    }

    $Script:CopyFiles = @()
    if ($CopyFiles)
    {
        $Script:CopyFiles += $CopyFiles
    }
    
    $Script:DebuggerPath = "Debugger"
    $Script:StartDebuggerScript = "StartDebugger.ps1"
}

Function Test-Paths([String[]]$Packages, [String[]]$ServicingPackages, [String]$UnattendPath)
{
    Write-Verbose -Message $Strings.MSG_CHECKING_PATHS

    if ($Script:HasMediaPath)
    {
        # Check media directory structure.
        if (!(Test-Path -Path $Script:NanoPath))
        {
            Throw ($Strings.ERR_DIRECTORY_DOES_NOT_EXIST_IN_MEDIA_DIRECTORY -f "NanoServer")
        }
        if (!(Test-Path -Path $Script:PackagesPath))
        {
            Throw ($Strings.ERR_DIRECTORY_DOES_NOT_EXIST_IN_DIRECTORY -f "Packages", "NanoServer", $Script:NanoPath)
        }
        if (!(Test-Path -Path $Script:LanguagePackagesPath))
        {
            Throw ($Strings.ERR_DIRECTORY_DOES_NOT_EXIST_IN_DIRECTORY -f $Language, "Packages", $Script:PackagesPath)
        }

        if (!(Test-Path -Path $Script:SourcesPath))
        {
            Throw ($Strings.ERR_DIRECTORY_DOES_NOT_EXIST_IN_MEDIA_DIRECTORY -f "Sources")
        }
        
        # Check that the Nano Server image is present in the media path.
        if (!(Test-Path -Path $Script:ImageFilePath))
        {
            Throw ($Strings.ERR_IMAGE_DOES_NOT_EXIST -f $IMAGE_NAME)
        }
    }
    else
    {
        # Check base directory structure.
        if (!(Test-Path -Path $Script:BasePath) -and !$script:Internal)
        {
            Throw $Strings.ERR_BASE_DIRECTORY_DOES_NOT_EXIST
        }
        if (!(Test-Path -Path $Script:BaseToolsPath))
        {
            Throw ($Strings.ERR_DIRECTORY_DOES_NOT_EXIST_IN_BASE_DIRECTORY -f "Tools")
        }
        if (!$Script:Internal -and !(Test-Path -Path $Script:BasePackagesPath))
        {
            Throw ($Strings.ERR_DIRECTORY_DOES_NOT_EXIST_IN_BASE_DIRECTORY -f "Packages")
        }

        if (!$Script:Internal -and !(Test-Path -Path $Script:BaseLanguagePackagesPath))
        {
            Write-Output -InputObject ($Strings.ERR_DIRECTORY_DOES_NOT_EXIST_IN_DIRECTORY -f $Language, "Packages", $Script:BasePackagesPath)
        }

        # Check that the Nano Server image is present in the base path.
        if (!(Test-Path -Path $Script:BaseWimImageFilePath) -and !$script:Internal -and $Script:NewImage)
        {
            Throw ($Strings.ERR_IMAGE_DOES_NOT_EXIST_IN_BASE_DIRECTORY -f $IMAGE_NAME)
        }
    }

    # Check that the existing image actually exists
    if (!$Script:HasMediaPath)
    {
        if (!$Script:NewImage -and (!$Script:TargetImageFilePath -or !(Test-Path -Path $Script:TargetImageFilePath)))
        {
            Throw $Strings.ERR_SPECIFIED_IMAGE_DOES_NOT_EXIST
        }
    }

    # Check that the given drivers path exists.
    if ($Script:DriversPath -and !(Test-Path -Path $Script:DriversPath))
    {
        Throw ($Strings.ERR_DRIVERS_DIRECTORY_DOES_NOT_EXIST -f $Script:DriversPath)
    }

    # Check that the image converter script is present.
    if ($Script:ImageConverterPath)
    {
        if (!(Test-Path -Path $Script:ImageConverterPath))
        {
            Throw ($Strings.ERR_IMAGE_CONVERTER_SCRIPT_DOES_NOT_EXIST -f $IMAGE_CONVERTER)
        }
    }

    if (-not $Script:Internal)
    {
        if ($Script:HasMediaPath)
        {
            # Check that the files for the requested packages are present in the media directory.
            $PackagesNotFound = $Script:PackageFilePaths.GetEnumerator() | Where-Object { (($Packages -Contains $_.Key) -and !(Test-Path -Path $_.Value)) }
            $LanguagePackagesNotFound = $Script:LanguagePackageFilePaths.GetEnumerator() | Where-Object { (($Packages -Contains $_.Key) -and !(Test-Path -Path $_.Value)) }
        }
        else
        {
            # Check that the files for the requested packages are present in the base directory.
            $PackagesNotFound = $Script:BasePackageFilePaths.GetEnumerator() | Where-Object { (($Packages -Contains $_.Key) -and !(Test-Path -Path $_.Value)) }
            $LanguagePackagesNotFound = $Script:BaseLanguagePackageFilePaths.GetEnumerator() | Where-Object { (($Packages -Contains $_.Key) -and !(Test-Path -Path $_.Value)) }
        }
    }
    else
    {
        $PackagesNotFound = $Null
        $LanguagePackagesNotFound = $Null
    }
    $ServicingPackagesNotFound = $Null
    if ($ServicingPackages)
    {
        $ServicingPackagesNotFound = $ServicingPackages | Where-Object { !(Test-Path -Path $_) }
    }

    if ($PackagesNotFound)
    {
        $PackagesNotFound | ForEach-Object { Write-Log $LEVEL_WARNING ($Strings.ERR_PACKAGE_DOES_NOT_EXIST -f $_.Value) }
    }
    if ($LanguagePackagesNotFound)
    {
        $LanguagePackagesNotFound | ForEach-Object { Write-Log $LEVEL_WARNING ($Strings.ERR_LANGUAGE_PACKAGE_DOES_NOT_EXIST -f $_.Value) }
    }
    if ($ServicingPackagesNotFound)
    {
        $ServicingPackagesNotFound | ForEach-Object { Write-Log $LEVEL_WARNING ($Strings.ERR_PACKAGE_DOES_NOT_EXIST -f $_) }
    }

    if ($PackagesNotFound -or $LanguagePackagesNotFound -or $ServicingPackagesNotFound)
    {
        Throw $Strings.ERR_ONE_OR_MORE_PACKAGES_DO_NOT_EXIST
    }
    
    # Check that the specified domain blob path exists.
    if ($Script:DomainBlobPath -and !(Test-Path -Path $Script:DomainBlobPath))
    {
        Throw $Strings.ERR_DOMAIN_BLOB_DOES_NOT_EXIST
    }

    if ($Script:CopyFiles -and ($Script:CopyFiles | Where-Object { !(Test-Path -Path $_) }))
    {
        Throw $Strings.ERR_COPY_FILES_DOES_NOT_EXIST
    }
    
    if ($UnattendPath -and !(Test-Path $UnattendPath))
    {
        Throw $Strings.ERR_UNATTEND_TEMPLATE_DOES_NOT_EXIST
    }
}

Function Initialize-Paths()
{
    Write-Verbose -Message $Strings.MSG_CREATING_PATHS

    New-Item -ItemType Directory -Force -Path $Script:BasePath | Write-Verbose
    
    if (!$Internal)
    {
        New-Item -ItemType Directory -Force -Path $Script:BaseToolsPath | Write-Verbose
        New-Item -ItemType Directory -Force -Path $Script:BasePackagesPath | Write-Verbose
        New-Item -ItemType Directory -Force -Path $Script:BaseLanguagePackagesPath | Write-Verbose

        $ResetTargetPath = $True
        if (Test-Path $Script:TargetPath)
        {
            $TP = Get-Item $Script:TargetPath
            if ($TP.Root.FullName -eq $TP.FullName)
            {
                $ResetTargetPath = $False
            }
        }
        if ($ResetTargetPath)
        {
            New-Item -ItemType Directory -Force -Path $Script:TargetPath | Write-Verbose
        }
    }
    
    New-Item -ItemType Directory -Force -Path $Script:TargetMountPath  | Write-Verbose
    New-Item -ItemType Directory -Force -Path $Script:TargetMountEspPath  | Write-Verbose

    $Script:TargetMountPath = (Resolve-Path -Path $Script:TargetMountPath).ProviderPath 
    $Script:TargetMountEspPath = (Resolve-Path -Path $Script:TargetMountEspPath).ProviderPath  
}

### -----------------------------------
### Phase 1
### -----------------------------------

Function Copy-Files()
{
    if (!$Script:HasMediaPath)
    {
        Write-Verbose -Message $Strings.MSG_SKIPPING_FILE_COPY

        return
    }

    Write-Verbose -Message $Strings.MSG_COPYING_FILES
    Write-Progress -Activity $Strings.MSG_COPYING_FILES

    # Copy the tools (exclude the large, unnecessary WIM's in that folder).
    if (!$Script:Internal)
    {
        Copy-Item -Path $Script:SourcesPath\* -Destination $Script:BaseToolsPath -Exclude *.wim -Force
    }

    # Copy the image
    Copy-Item -Path $Script:ImageFilePath -Destination $Script:BasePath -Force

    # Copy the packages
    Copy-Item -Path $Script:PackagesPath\*.cab -Destination $Script:BasePackagesPath -Force
    Copy-Item -Path $Script:LanguagePackagesPath\*.cab -Destination $Script:BaseLanguagePackagesPath -Force
}

Function Enable-RamdiskBoot()
{
    $cmdTemplate = "& '{0}' /Export-Image /SourceImageFile:'{1}' /SourceIndex:1 /DestinationImageFile:'{1}' /Bootable /LogLevel:2 /LogPath:'{2}'"
    $cmd = ($cmdTemplate -f $Script:BaseDismFilePath, $Script:TargetImageFilePath, $Script:DismLogFile)
    Invoke-ExternalCommand $cmd
    
    $cmdTemplate = "& '{0}' /Delete-Image /ImageFile:'{1}' /Index:1 /LogLevel:2 /LogPath:'{2}'"
    $cmd = ($cmdTemplate -f $Script:BaseDismFilePath, $Script:TargetImageFilePath, $Script:DismLogFile)
    Invoke-ExternalCommand $cmd
}

Function Export-WimImage([String]$Edition)
{
    $cmdTemplate = "& '{0}' /Export-Image /SourceImageFile:'{1}' /SourceIndex:{2} /DestinationImageFile:'{3}' /LogLevel:2 /LogPath:'{4}'"
    $cmd = ($cmdTemplate -f $Script:BaseDismFilePath, $Script:BaseWimImageFilePath, $Script:Editions[$Edition], $Script:BaseImageFilePath, $Script:DismLogFile)
    Invoke-ExternalCommand $cmd
}

Function Export-VhdImage([String]$Edition)
{
    $Parameters = @{}
    $Parameters["-SourcePath"] = $Script:BaseWimImageFilePath
    $Parameters["-VHDPath"] = $Script:BaseImageFilePath
    $Parameters["-VHDFormat"] = $Script:ImageFormat
    $Parameters["-EnableDebugger"] = "None"
    $Parameters["-Edition"] = $Script:Editions[$Edition]
    if ($Script:ImageFormat -eq "vhdx")
    {
        $Parameters["-DiskLayout"] = "UEFI"
    }
    else
    {
        $Parameters["-DiskLayout"] = "BIOS"
    }
    $Parameters["-SizeBytes"] = $Script:MaxSize

    if (!(Get-Command Convert-WindowsImage -ErrorAction SilentlyContinue))
    {
        . $Script:ImageConverterPath
    }

    Convert-WindowsImage @Parameters
}

Function Convert-Image([String]$Edition)
{
    Write-Verbose -Message $Strings.MSG_CONVERTING_IMAGE
    Write-Progress -Activity $Strings.MSG_CONVERTING_IMAGE

    if ($Script:ImageFormat -eq "wim")
    {
        Export-WimImage $Edition
    }
    else
    {
        Export-VhdImage $Edition
    }   
        
    if (-not (Test-Path $Script:BaseImageFilePath))
    {
        Throw $Strings.ERR_IMAGE_WAS_NOT_PRODUCED
    }
    
    Move-Item -Path $Script:BaseImageFilePath -Destination $Script:TargetImageFilePath -Force
}

### -----------------------------------
### Phase 2
### -----------------------------------

Function Add-Files()
{
    if (!$Script:CopyFiles)
    {
        Write-Verbose -Message $Strings.MSG_SKIPPING_COPYING_FILES_TO_IMAGE
    
        return
    }
    
    Write-Verbose -Message $Strings.MSG_COPYING_FILES_TO_IMAGE
    Write-Progress -Activity $Strings.MSG_COPYING_FILES_TO_IMAGE
    
    $Script:CopyFiles | ForEach-Object {
        Copy-Item -Recurse -Force -Path $_ -Destination $Script:TargetMountPath
    }
}

Function Add-Packages([String[]]$Packages, [String[]]$ServicingPackages)
{
    if (!$Packages -and !$ServicingPackages)
    {
        Write-Verbose -Message $Strings.MSG_SKIPPING_PACKAGE_ADDITION
        
        return
    }

    Write-Verbose -Message $Strings.MSG_ADDING_PACKAGES
    Write-Progress -Activity $Strings.MSG_ADDING_PACKAGES

    if ($Packages)
    {
        $Packages | ForEach-Object { 
            Add-Package $Script:BasePackageFilePaths[$_] $False
            Add-Package $Script:BaseLanguagePackageFilePaths[$_] $True 
        }
    }
    
    if ($ServicingPackages)
    {
        $ServicingPackages | ForEach-Object { 
            Add-Package $_ $False
        }
    }
}

Function Add-Package([String]$PackageFilePath, [Bool]$IsLanguage)
{
    $PackageFilePath = (Resolve-Path "$PackageFilePath*").ProviderPath 
    $PackageName = Get-PackageName $PackageFilePath

    if ($IsLanguage)
    {        
        $Message = $Strings.MSG_ADDING_LANGUAGE_PACKAGE -f $PackageName
    }
    else
    {
        $Message = $Strings.MSG_ADDING_PACKAGE -f $PackageName
    }

    Write-Progress -Id 1 -Activity $Message

    
    $ExitCode = Invoke-ExternalCommand "& '$Script:BaseDismFilePath' /Add-Package /PackagePath:'$PackageFilePath' /Image:'$Script:TargetMountPath' /LogLevel:2 /LogPath:'$Script:DismLogFile'" -ReturnExitCode
    if ($ExitCode)
    {
        if ($ExitCode -eq 0x800f081e)
        {
            Throw ($Strings.ERR_PACKAGE_NOT_APPLICABLE -f $PackageName)
        }
        else
        {
            Throw ($Strings.ERR_EXTERNAL_CMD -f $ExitCode)
        }
    }

    Write-Progress -Id 1 -Activity $Message -Completed
}

Function Add-Drivers([Bool]$Development)
{
    if (!$Script:DriversPath)
    {
        Write-Verbose -Message $Strings.MSG_SKIPPING_DRIVER_ADDITION

        return
    }

    Write-Verbose -Message $Strings.MSG_ADDING_DRIVERS
    Write-Progress -Activity $Strings.MSG_ADDING_DRIVERS
    
    $CmdTemplate = "& '{0}' /Add-Driver /Driver:'{1}' /Recurse /Image:'{2}' /LogLevel:2 /LogPath:'{3}'"
    $Cmd = $CmdTemplate -f $Script:BaseDismFilePath, $Script:DriversPath, $Script:TargetMountPath, $Script:DismLogFile
    
    if ($Development)
    {
        $Cmd += " /ForceUnsigned"
    }
    
    Invoke-ExternalCommand $Cmd
}

Function Add-Debugger()
{
    Write-Verbose -Message $Strings.MSG_ADDING_DEBUGGER
    Write-Progress -Activity $Strings.MSG_ADDING_DEBUGGER
    
    Copy-Item -Path $VSDebuggerBinariesPath -Destination (Join-Path -Path $Script:TargetMountPath -ChildPath $Script:DebuggerPath) -Recurse
    
    $System32Path = Join-Path -Path $Script:TargetMountPath -ChildPath "Windows\System32"
    
    Copy-Item -Path (Join-Path -Path $Script:VSCRTReleaseBinariesPath -ChildPath "vcruntime140.dll") -Destination $System32Path
    Copy-Item -Path (Join-Path -Path $Script:VSCRTReleaseBinariesPath -ChildPath "msvcp140.dll") -Destination $System32Path
    Copy-Item -Path (Join-Path -Path $Script:VSCRTDebugBinariesPath -ChildPath "vcruntime140d.dll") -Destination $System32Path
    Copy-Item -Path (Join-Path -Path $Script:VSCRTDebugBinariesPath -ChildPath "msvcp140d.dll") -Destination $System32Path
    Copy-Item -Path (Join-Path -Path $Script:VSUCRTBinariesPath -ChildPath "ucrtbased.dll") -Destination $System32Path
    
    $StartDebuggerPath = Join-Path -Path $Script:TargetMountPath -ChildPath $Script:StartDebuggerScript
    Write-Output ("Start `$Env:SystemDrive\{0}\msvsmon.exe -ArgumentList /nowowwarn,/noauth,/anyuser,/nosecuritywarn,/timeout:36000" -f $Script:DebuggerPath) | Out-File -FilePath $StartDebuggerPath
    
    Write-Log $LEVEL_OUTPUT ($Strings.MSG_START_DEBUGGER -f (Join-Path -Path "C:\" -ChildPath $Script:StartDebuggerScript))
    
    Mount-RegistryHive "SOFTWARE"
    Try
    {
        Add-Registry "Policies\Microsoft\Windows\Appx" "/v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1 /f"
        Add-Registry "Microsoft\Windows\CurrentVersion\AppModelUnlock" "/v AllowAllTrustedApps /t REG_DWORD /d 1 /f"
        Add-Registry "Microsoft\Windows\CurrentVersion\AppModelUnlock" "/v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1 /f"
    }
    Finally
    {
        Unmount-RegistryHive
    }
}

### -----------------------------------
### Phase 3
### -----------------------------------

Function ConvertTo-String([SecureString]$SecureString)
{
    if (-not $SecureString)
    {
        return $null
    }

    $PointerToPasswordString = $Null
    try
    {
        $PointerToPasswordString = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($SecureString)
        $ManagedPasswordString = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($PointerToPasswordString)
    }
    finally
    {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($PointerToPasswordString)
    }
    
    return $ManagedPasswordString
}

Function Add-ServicingDescriptor([String]$ComputerName, [SecureString]$AdministratorPassword, [String]$UnattendPath)
{
    if (-not $ComputerName -and $Script:NewImage)
    {
        $ComputerName = "*"
    }

    if (-not $ComputerName -and -not $AdministratorPassword -and -not $UnattendPath)
    {
        return
    }
    
    Write-Verbose -Message $Strings.MSG_ADDING_UNATTEND
    Write-Progress -Activity $Strings.MSG_ADDING_UNATTEND
    
    if (-not $Script:NewImage -and $UnattendPath)
    {
        Write-Warning ($Strings.MSG_SETUPCOMPLETE_CHANGES_FOR_BOOTED_MEDIA -f "-UnattendPath")
    }
    
    # Write out the unattend.
    New-Unattend $ComputerName $AdministratorPassword
    
    # Embed the descriptor into the image.
    Invoke-ExternalCommand "& '$Script:BaseDismFilePath' /Image:'$Script:TargetMountPath' /Apply-Unattend:'$Script:TargetUnattendFilePath' /LogLevel:2 /LogPath:'$Script:DismLogFile'"
    
    # Copy the unattend over.
    if ($UnattendPath)
    {
        Invoke-ExternalCommand "& '$Script:BaseDismFilePath' /Image:'$Script:TargetMountPath' /Apply-Unattend:'$UnattendPath' /LogLevel:2 /LogPath:'$Script:DismLogFile'"
        New-Item -ItemType Directory -Force -Path $Script:TargetMountPath\Windows\Panther | Out-Null
        Copy-Item -Path $UnattendPath -Destination $Script:TargetMountPath\Windows\Panther\Unattend.xml -Force
    }
}

Function New-Unattend([String]$ComputerName, [SecureString]$AdministratorPassword)
{
    $Xml = New-Object -TypeName Xml
    $XmlNs = "urn:schemas-microsoft-com:unattend"
    
    $XmlDecl = $Xml.CreateXmlDeclaration("1.0", "utf-8", $Null)
    $XmlRoot = $Xml.DocumentElement
    $Xml.InsertBefore($XmlDecl, $XmlRoot) | Out-Null

    $XmlUnattended = $Xml.CreateElement("unattend", $XmlNs)
    $XmlUnattended.SetAttribute("xmlns:wcm", "http://schemas.microsoft.com/WMIConfig/2002/State")
    $XmlUnattended.SetAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    $Xml.AppendChild($XmlUnattended) | Out-Null

    if ($AdministratorPassword)
    {
        Write-AdministratorPasswordXml $Xml $XmlNs $XmlUnattended $AdministratorPassword
    }

    if ($ComputerName)
    {
        Write-ComputerNameXml $Xml $XmlNs $XmlUnattended $ComputerName
    }
    
    # Normal .NET methods are unaware of the PowerShell context. In this case,
    # the path to save the XML to is relative. While PowerShell would resolve
    # it as we would expect, the .NET method will do so relative to its working
    # directory, which is not necessarily the same as PowerShell's. So, we need
    # to expand the relative path manually.
    $TargetPath = $Script:TargetUnattendFilePath
    if (-not [System.IO.Path]::IsPathRooted($TargetPath))
    {
        $TargetPath = Join-Path -Path (Get-Location) -ChildPath $Script:TargetUnattendFilePath
    }
    
    $Xml.Save([System.IO.Path]::GetFullPath($TargetPath))
}

Function Write-ComputerNameXml([Xml]$Xml, [String]$XmlNs, [System.Xml.XmlElement]$XmlUnattended, [String]$ComputerName)
{
    if (-not (Get-Member -InputObject $XmlUnattended -Name "settings"))
    {
        $XmlSettings = $Xml.CreateElement("settings", $XmlNs)
        $XmlSettings.SetAttribute("pass", "offlineServicing")
        $XmlUnattended.AppendChild($XmlSettings) | Out-Null
    }
    $XmlSettings = $XmlUnattended.settings
    
    if (-not (Get-Member -InputObject $XmlSettings -Name "component"))
    {
        $XmlComponent = $Xml.CreateElement("component", $XmlNs)
        $XmlComponent.SetAttribute("name", "Microsoft-Windows-Shell-Setup")
        $XmlComponent.SetAttribute("processorArchitecture", "amd64")
        $XmlComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
        $XmlComponent.SetAttribute("language", "neutral")
        $XmlComponent.SetAttribute("versionScope", "nonSxS")
        $XmlSettings.AppendChild($XmlComponent) | Out-Null
    }
    $XmlComponent = $XmlSettings.component

    $XmlComputerName = $Xml.CreateElement("ComputerName", $XmlNs)
    $XmlName = $Xml.CreateTextNode($ComputerName)
    $XmlComputerName.AppendChild($XmlName) | Out-Null
    $XmlComponent.AppendChild($XmlComputerName) | Out-Null
}

Function Write-AdministratorPasswordXml([Xml]$Xml, [String]$XmlNs, [System.Xml.XmlElement]$XmlUnattended, [SecureString]$AdministratorPassword)
{
    $XmlSettings = $Xml.CreateElement("settings", $XmlNs)
    $XmlSettings.SetAttribute("pass", "offlineServicing")
    $XmlUnattended.AppendChild($XmlSettings) | Out-Null
    $XmlComponent = $Xml.CreateElement("component", $XmlNs)
    $XmlComponent.SetAttribute("name", "Microsoft-Windows-Shell-Setup")
    $XmlComponent.SetAttribute("processorArchitecture", "amd64")
    $XmlComponent.SetAttribute("publicKeyToken", "31bf3856ad364e35")
    $XmlComponent.SetAttribute("language", "neutral")
    $XmlComponent.SetAttribute("versionScope", "nonSxS")
    $XmlSettings.AppendChild($XmlComponent) | Out-Null
    $XmlUserAccounts = $Xml.CreateElement("OfflineUserAccounts", $XmlNs)
    $XmlComponent.AppendChild($XmlUserAccounts) | Out-Null

    $XmlAdministratorPassword = $Xml.CreateElement("OfflineAdministratorPassword", $XmlNs)
    $XmlUserAccounts.AppendChild($XmlAdministratorPassword) | Out-Null
    
    $XmlValue = $Xml.CreateElement("Value", $XmlNs)
    $XmlText = $Xml.CreateTextNode([Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((ConvertTo-String $AdministratorPassword) + "OfflineAdministratorPassword")))
    $XmlValue.AppendChild($XmlText) | Out-Null
    $XmlAdministratorPassword.AppendChild($XmlValue) | Out-Null

    $XmlPlainText = $Xml.CreateElement("PlainText", $XmlNs)
    $XmlPassword = $Xml.CreateTextNode("false")
    $XmlPlainText.AppendChild($XmlPassword) | Out-Null
    $XmlAdministratorPassword.AppendChild($XmlPlainText) | Out-Null
}

Function Join-Domain([String]$ComputerName, [String]$DomainName, [Bool]$ReuseDomainNode)
{
    # If the target image must join a domain, but a blob was not provided, one
    # must be harvested from the local machine.
    if ($DomainName -and !$Script:DomainBlobPath)
    {
        Write-Verbose -Message $Strings.MSG_COLLECTING_DOMAIN_BLOB

        $Command = "djoin /Provision /Domain $DomainName /Machine $ComputerName /SaveFile '$Script:TargetDomainBlobPath'"
        if ($ReuseDomainNode)
        {
            $Command += " /Reuse"
        }

        try
        {
            Invoke-ExternalCommand $Command
        }
        catch
        {
            if ($LastExitCode -eq 2224)
            {
                Throw $Strings.ERR_REUSE_DOMAIN_NAME
            }
            else
            {
                Throw
            }
        }

        $Script:DomainBlobPath = $Script:TargetDomainBlobPath
    }

    if ($Script:DomainBlobPath)
    {
        Write-Verbose -Message $Strings.MSG_JOINING_DOMAIN

        Invoke-ExternalCommand "djoin /RequestODJ /LoadFile '$Script:DomainBlobPath' /WindowsPath '$Script:TargetMountPath\Windows'"
    }
}

### -----------------------------------
### Phase 4
### -----------------------------------

Function Enable-TestSigning([String]$BCDPath, [String]$BCDTemplatePath)
{
    Write-Verbose -Message $Strings.MSG_ENABLING_TESTSIGNING
    Write-Progress -Activity $Strings.MSG_ENABLING_TESTSIGNING
 
    if ($BCDPath)
    {
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /set ``{default``} TestSigning ON")
    }
    
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /set $BCD_TEMPLATE_PCAT_ENTRY TestSigning ON")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /set $BCD_TEMPLATE_EFI_ENTRY TestSigning ON")
}


Function Enable-Debug([String]$BCDPath, [String]$BCDTemplatePath)
{
    Write-Verbose -Message $Strings.MSG_ENABLING_DEBUG
    Write-Progress -Activity $Strings.MSG_ENABLING_DEBUG
 
    if ($BCDPath)
    {
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /BootDebug ``{bootmgr``} ON")
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /BootDebug ``{default``} ON")
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /Debug ``{default``} ON")
    }
    
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /BootDebug ``{bootmgr``} ON")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /BootDebug $BCD_TEMPLATE_PCAT_ENTRY ON")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /Debug $BCD_TEMPLATE_PCAT_ENTRY ON")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /BootDebug $BCD_TEMPLATE_EFI_ENTRY ON")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /Debug $BCD_TEMPLATE_EFI_ENTRY ON")
}

Function Enable-DebugSerial([String]$BCDPath, [String]$BCDTemplatePath, [Int]$Port, [Int]$BaudRate)
{
    if ($BCDPath)
    {
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /DBGSettings SERIAL DEBUGPORT:$Port BAUDRATE:$BaudRate")
    }
    
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /DBGSettings SERIAL DEBUGPORT:$Port BAUDRATE:$BaudRate")
}

Function Extract-KdnetKey([String]$BcdEditOutput)
{
    if ($BcdEditOutput -Match "^Key=(.+)$")
    {
        return $Matches[1]
    }
    else
    {
        Throw $Strings.ERR_KDNET_KEY_NOT_PRODUCED
    }
}

Function Enable-DebugNet([String]$BCDPath, [String]$BCDTemplatePath, [String]$RemoteIP, [String]$RemotePort, [String]$Key)
{
    if ($BCDPath)
    {
        $Command = "bcdedit /Store '$BCDPath' /DBGSettings NET HOSTIP:$RemoteIP PORT:$RemotePort"
        if ($Key)
        {
            $Command += " KEY:$Key"
        }

        $Key = Extract-KdnetKey (Invoke-ExternalCommand $Command -ReturnOutput -DisableRedirect)
    }
    
    $Command = "bcdedit /Store '$BCDTemplatePath' /DBGSettings NET HOSTIP:$RemoteIP PORT:$RemotePort"
    if ($Key)
    {
        $Command += " KEY:$Key"
    }
    Extract-KdnetKey (Invoke-ExternalCommand $Command -ReturnOutput -DisableRedirect) | Out-File -FilePath $Script:TargetDebuggingKeyFilePath
    
    Write-Log $LEVEL_OUTPUT ($Strings.MSG_KERNEL_DEBUG_KEY_FILE -f $Script:TargetDebuggingKeyFilePath)
}

Function Enable-DebugFirewire([String]$BCDPath, [String]$BCDTemplatePath, [Int]$Channel)
{
    if ($BCDPath)
    {
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /DBGSettings 1394 Channel:$Channel")
    }
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /DBGSettings 1394 Channel:$Channel")
}

Function Enable-DebugUSB([String]$BCDPath, [String]$BCDTemplatePath, [String]$TargetName)
{
    if ($BCDPath)
    {
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /DBGSettings USB TargetName:$TargetName")
    }
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /DBGSettings USB TargetName:$TargetName")
}

Function Enable-EMS([String]$BCDPath, [String]$BCDTemplatePath, [Int]$Port, [Int]$BaudRate)
{
    Write-Verbose -Message $Strings.MSG_ENABLING_EMS
    Write-Progress -Activity $Strings.MSG_ENABLING_EMS

    if ($BCDPath)
    {
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /EMSSettings EMSPORT:$Port EMSBAUDRATE:$BaudRate")
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /EMS ``{default``} ON")
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /BootEMS ``{default``} ON")
        Invoke-ExternalCommand("bcdedit /Store '$BCDPath' /BootEMS ``{bootmgr``} ON")
    }
    
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /EMSSettings EMSPORT:$Port EMSBAUDRATE:$BaudRate")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /EMS $BCD_TEMPLATE_PCAT_ENTRY ON")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /BootEMS $BCD_TEMPLATE_PCAT_ENTRY ON")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /EMS $BCD_TEMPLATE_EFI_ENTRY ON")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /BootEMS $BCD_TEMPLATE_EFI_ENTRY ON")
    Invoke-ExternalCommand("bcdedit /Store '$BCDTemplatePath' /BootEMS ``{bootmgr``} ON")
}

Function Write-SetupComplete(
    [Bool]$OpenPort,
    [String]$InterfaceNameOrIndex,
    [String]$Ipv6Address,
    [String[]]$Ipv6Dns,
    [String]$Ipv4Address,
    [String]$Ipv4SubnetMask,
    [String]$Ipv4Gateway,
    [String[]]$Ipv4Dns,
    [String[]]$SetupCompleteCommands,
    [Bool]$Development)
{
    if (-not $Script:NewImage)
    {
        Write-Warning ($Strings.MSG_SETUPCOMPLETE_CHANGES_FOR_BOOTED_MEDIA -f "-InterfaceNameOrIndex, -Ipv6Address, -Ipv6Dns, -Ipv4Address, -Ipv4SubnetMask, -Ipv4Gateway, -Ipv4Dns, -SetupCompleteCommands, -Development")
    }

    $Scripts = "$Script:TargetMountPath\Windows\Setup\Scripts"
    $SetupComplete = Join-Path $Scripts "setupcomplete.cmd"
    if (Test-Path ($SetupComplete))
    {
        $SetupCompleteCommandsAll = Get-Content $SetupComplete
    }
    else
    {
        New-Item -ItemType Directory -Force -Path $Scripts | Out-Null
        $SetupCompleteCommandsAll = @("@ECHO OFF")
    }
    
    if ($SetupCompleteCommands)
    {
        $SetupCompleteCommandsAll += $SetupCompleteCommands
    }
    
    if ($Ipv6Address)
    {
        $SetupCompleteCommandsAll += "netsh interface ipv6 set address `"$InterfaceNameOrIndex`" $Ipv6Address"
    }
    if ($Ipv6Dns)
    {
        $first = $Ipv6Dns[0]
        $SetupCompleteCommandsAll += "netsh interface ipv6 set dnsservers `"$InterfaceNameOrIndex`" static $first"
        for ($i = 2; $i -le $Ipv6Dns.Count; $i++)
        {
            $next = $Ipv6Dns[$i - 1]
            $SetupCompleteCommandsAll += "netsh interface ipv6 add dnsservers `"$InterfaceNameOrIndex`" $next index=$i"
        }
    }
    if ($Ipv4Address)
    {
        $SetupCompleteCommandsAll += "netsh interface ipv4 set address `"$InterfaceNameOrIndex`" static $Ipv4Address $Ipv4SubnetMask $Ipv4Gateway"
    }
    if ($Ipv4Dns)
    {
        $first = $Ipv4Dns[0]
        $SetupCompleteCommandsAll += "netsh interface ipv4 set dnsservers `"$InterfaceNameOrIndex`" static $first"
        for ($i = 2; $i -le $Ipv4Dns.Count; $i++)
        {
            $next = $Ipv4Dns[$i - 1]
            $SetupCompleteCommandsAll += "netsh interface ipv4 add dnsservers `"$InterfaceNameOrIndex`" $next index=$i"
        }
    }
    if ($OpenPort)
    {
        $SetupCompleteCommandsAll += "netsh advfirewall firewall add rule name=`"WinRM 5985`" protocol=TCP dir=in localport=5985 profile=any action=allow"
    }
    
    if ($Development)
    {
        $cmd = "netsh advfirewall firewall add rule name=`"Remote Debugger`" dir=in action=allow program=`"%SystemDrive%\{0}`" enable=yes"
        $SetupCompleteCommandsAll += ($cmd -f (Join-Path -Path $Script:DebuggerPath -ChildPath "msvsmon.exe"))
    }
    
    $SetupCompleteCommand = ($SetupCompleteCommandsAll -Join "`r`n")
    
    # To populate the batch file, the > and >> operators cannot be used. The
    # resulting file must be encoded in ASCII.
    Set-Content -Value $SetupCompleteCommand -Path "$Script:TargetSetupCompleteFilePath" -Encoding ASCII
    
    Copy-Item -Path $Script:TargetSetupCompleteFilePath -Destination "$Script:TargetMountPath\Windows\Setup\Scripts" -Force
}

### -----------------------------------
### Helper Methods
### -----------------------------------

Function Mount-RegistryHive([String]$Hive)
{
    $Script:RegistryPrefix = "NSIG"

    $Script:RegMountPoint = "HKLM\{0}" -f $script:RegistryPrefix
    Invoke-ExternalCommand ("reg load {0} '{1}\Windows\System32\Config\{2}'" -f $script:RegMountPoint, $Script:TargetMountPath, $Hive)
}

Function Unmount-RegistryHive()
{
    Invoke-ExternalCommand ("reg unload {0}" -f $script:RegMountPoint)
}

Function Add-Registry([String]$Where, [String]$What)
{
    Invoke-ExternalCommand ("reg add '{0}\{1}' {2}" -f $Script:RegMountPoint, $Where, $What)
}

Function Mount-Image()
{
    Write-Verbose -Message $Strings.MSG_MOUNTING_IMAGE
    Write-Progress -Activity $Strings.MSG_MOUNTING_IMAGE

    $Script:TargetImageFilePath = (Resolve-Path -Path $Script:TargetImageFilePath).ProviderPath 
    if ($Script:ImageFormat -eq "vhdx")
    {
        Mount-ImageInternal
    }
    else
    {
        Invoke-ExternalCommand "& '$Script:BaseDismFilePath' /Mount-Image /ImageFile:'$Script:TargetImageFilePath' /MountDir:'$Script:TargetMountPath' -Index:1 /LogLevel:2 /LogPath:'$Script:DismLogFile'"
    }
}

Function Dismount-Image([Switch]$Discard)
{
    Write-Verbose -Message $Strings.MSG_DISMOUNTING_IMAGE
    Write-Progress -Activity $Strings.MSG_DISMOUNTING_IMAGE

    if ($Script:ImageFormat -eq "vhdx")
    {
        Dismount-ImageInternal
    }
    else
    {
        if ($Discard)
        {
            Invoke-ExternalCommand "& '$Script:BaseDismFilePath' /Unmount-Image /MountDir:'$Script:TargetMountPath' /Discard /LogLevel:2 /LogPath:'$Script:DismLogFile'"
        }
        else
        {
            Invoke-ExternalCommand "& '$Script:BaseDismFilePath' /Unmount-Image /MountDir:'$Script:TargetMountPath' /Commit /LogLevel:2 /LogPath:'$Script:DismLogFile'"
        }
    }
}

Function Mount-ImageInternal()
{
    Mount-DiskImage -ImagePath $Script:TargetImageFilePath -NoDriveLetter
    try
    {
        $disk = Get-DiskImage -ImagePath $Script:TargetImageFilePath | Get-Disk
        $partition = $disk | Get-Partition | Where-Object { $_.Type -eq "IFS" -or $_.Type -eq "Basic" }
        $partition | Add-PartitionAccessPath -AccessPath $Script:TargetMountPath -ErrorAction Stop
    }
    catch
    {
        Dismount-DiskImage -ImagePath $Script:TargetImageFilePath
    }
}

Function Dismount-ImageInternal()
{
    try
    {
        $disk = Get-DiskImage -ImagePath $Script:TargetImageFilePath | Get-Disk
        $partition = $disk | Get-Partition | Where-Object { $_.Type -eq "IFS" -or $_.Type -eq "Basic" }
        $partition | Remove-PartitionAccessPath -AccessPath $Script:TargetMountPath -ErrorAction Stop
    }
    finally
    {
        Dismount-DiskImage -ImagePath $Script:TargetImageFilePath
    }
}

Function Mount-AsBasicData()
{
    $disk = Get-DiskImage -ImagePath $Script:TargetImageFilePath | Get-Disk
    $diskId = $disk.Number
    $partition = $disk | Get-Partition | Where-Object { $_.Type -eq "System" }
    $partId = $partition.PartitionNumber
    $partGuid = $partition.Guid
    
    $DiskpartScript = Join-Path -Path $Script:TargetTempPath -ChildPath "diskpart.txt"
    
    $DiskpartCommands = "select disk $diskId`nselect partition $partId`nset id=ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
    $DiskpartCommands | Out-File -Encoding ASCII -FilePath $DiskpartScript

    Invoke-ExternalCommand "diskpart.exe /s $DiskpartScript"
    
    $partition | Add-PartitionAccessPath -AccessPath $Script:TargetMountEspPath -ErrorAction Stop
    Remove-Item $DiskpartScript
    
    return $partGuid
}

Function Dismount-AsSystemPartition([String]$guid)
{
    $partition = Get-Partition | Where-Object { $_.Guid -eq $guid }
    $diskId = $partition.DiskNumber
    $partId = $partition.PartitionNumber
    
    $partition | Remove-PartitionAccessPath -AccessPath $Script:TargetMountEspPath -ErrorAction Stop
    
    $DiskpartScript = Join-Path -Path $Script:TargetTempPath -ChildPath "diskpart.txt"

    $DiskpartCommands = "select disk $diskId`nselect partition $partId`nset id=c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    $DiskpartCommands | Out-File -Encoding ASCII -FilePath $DiskpartScript
    Invoke-ExternalCommand "diskpart.exe /s $DiskpartScript"
    
    Remove-Item $DiskpartScript
}

Function Invoke-ExternalCommand([String]$Command, [Switch]$ReturnOutput, [Switch]$DisableRedirect, [Switch]$ReturnExitCode)
{
    Write-Log $LEVEL_VERBOSE $Command
    if (-not $DisableRedirect)
    {
        $Command += " 2>&1"
    }
    $Output = (Invoke-Expression -Command $Command | Out-String)
    if ($LastExitCode)
    {
        Write-Log $LEVEL_NONE $Output -Verbose

        if (-not $ReturnExitCode)
        {
            Throw ($Strings.ERR_EXTERNAL_CMD -f $LastExitCode)
        }
    }
    
    if ($ReturnOutput)
    {
        return $Output
    }
    
    if ($ReturnExitCode)
    {
        return $LastExitCode
    }
}

Function Write-Log([String]$Level, [String]$Message, [Bool]$AppendNewLine = $False, [switch]$NoOutput)
{
    $LogMessage = $Message
    if ($AppendNewLine)
    {
        $LogMessage += "`n"
    }
    Write-Output -InputObject "$(Get-Date) $LogMessage" | Out-File -FilePath $Script:LogFile -Append

    if (-not $NoOutput)
    {
        switch ($Level)
        {
            { $_ -eq $LEVEL_WARNING } { Write-Warning -Message $Message }
            { $_ -eq $LEVEL_VERBOSE } { Write-Verbose -Message $Message }
            { $_ -eq $LEVEL_OUTPUT } { Write-Output -InputObject $Message }
        }
    }
}

Function Verify-MSVS14U1Installed()
{
    if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\DevDiv\VC\Servicing\14.0") -or
        -not (Test-Path -Path $Script:VSDebuggerBinariesPath) -or
        -not (Test-Path -Path $Script:VSCRTReleaseBinariesPath) -or
        -not (Test-Path -Path $Script:VSCRTDebugBinariesPath) -or
        -not (Test-Path -Path $Script:VSUCRTBinariesPath))
    {
        Throw $Strings.ERR_MSVS_REQUIRED
    }
}

Function Verify-UserIsAdministrator()
{
    $CurrentUser = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
    {
        Throw $Strings.ERR_USER_MUST_BE_ADMINISTRATOR
    }
}

Function New-DynamicParameter([String]$Name, [System.Type]$Type, $Value, [switch]$Mandatory, [switch]$NotNull)
{
    $ParamAttr = New-Object -TypeName System.Management.Automation.ParameterAttribute
    $ParamAttr.ParameterSetName  = "__AllParameterSets"
    $ParamAttr.Mandatory = $Mandatory

    $AttrCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
    $AttrCollection.Add($ParamAttr)

    $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList ($Name, $Type, $AttrCollection)

    if ($Value)
    {
        $Parameter.Value = $Value
    }

    return $Parameter
}

Function Write-LogHeader()
{
    Write-Log $LEVEL_NONE "========================================"
    Write-Log $LEVEL_NONE ($Strings.LOG_HEADER -f $PSCmdlet.MyInvocation.MyCommand.Name)
    Write-Log $LEVEL_NONE "========================================"

    $Params = ($PSCmdlet.MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object {
        "-{0}:{1}" -f $_.Key, $_.Value
    }) -Join " "

    Write-Log $LEVEL_NONE ("{0} {1}" -f $PSCmdlet.MyInvocation.MyCommand.Name, $Params)
}

Export-ModuleMember -Function New-NanoServerImage, Edit-NanoServerImage, Get-NanoServerPackage
