#Filename:            VMware_VM_Automation_vcsa65_updated_CICD.ps1
#Author:              Fabian Brash
#Date:                09-28-2016
#Modified:            05-14-2018
#Purpose:             Deploy and Customize a VM **Must be run in x86 version of Powershell or PowerCLI(Not longer accurate as of version 5.5.x this can be run in x64)



<#________   ________   ________
|\   __  \ |\   __  \ |\   ____\
\ \  \|\  \\ \  \|\  \\ \  \___|_
 \ \   _  _\\ \   ____\\ \_____  \
  \ \  \\  \|\ \  \___| \|____|\  \
   \ \__\\ _\ \ \__\      ____\_\  \
    \|__|\|__| \|__|     |\_________\
                         \|_________|#>


Clear-Host


try
    {
        Import-Module -Name VMware.VimAutomation.Core -ErrorAction Stop
    }
catch
    {
        Write-Error -Message "VmWare core automation module could not be loaded..."
    }

    try
        {
            Import-Module -Name VMware.VimAutomation.Vds -ErrorAction Stop
        }
    catch
        {
            Write-Error -Message "VMware core networking automation module could not be loaded..."
        }


$RPS_DataStore = "Tier2"
$RPS_DataStoreSQL = "DB"
$VMNetwork = "VMTraffic"
$vDSPG = "DvPG-VMTraffic99"
$vDSName = "DSwitch"
$VMName = "Srv16-CI-Test"
$RPS_Folder = 'Infra'
$RPS_FolderSQL = 'SQL'
$SourceCustomization = "Server2016-Customization_PowerCLI"
$SourceCustomization2012 = "Server2012R2-Customization_PowerCLI"
$SourceCustomizationLinux = "Linux-Spec"
$Subnet = '255.255.255.0'
$RPS_IPMode = 'UseStaticIp'
$RPS_IPAddress = ''
$Gateway = ''
$RPS_DNS = ''
$RPS_DNS2 = ''
$vCenter = "VCSA"
$RPS_Description = "Test CI build from Jenkins"
[int]$OSClass = 1


$VCSAUser = "user@vsphere.local"
$encrypted = Get-Content C:\passfile_CI.txt | ConvertTo-SecureString

<#-----------Let's decrypt our password-----------------------------#>
$PipeLine_password = (New-Object PSCredential "user",$encrypted).GetNetworkCredential().Password


Connect-ViServer -Server $vCenter -User $VCSAUser -Password $PipeLine_password

###Variables from inside vCenter

###Our Templates
$Srv2k12R2Template = "18-09-Srv2012R2-8K-T"
$Srv2k16Template = "18-09-Srv16-8K-T"
$Srv2k16SQLTemplate = "18-09-Srv16-SQL16-8K-EFI-T"
$CentOS = "18-05-CentOS-7-T"
$CentOSNode = "18-06-CentOS-7-NodeJS8-T"

##Our Target Cluster
$TargetCluster = Get-Cluster -Name "Nodes"

##Our vDS
$ProdvDSPG = Get-VDSwitch -Name $vDSName | Get-VDPortgroup -Name $vDSPG


<#---Let's get all VM's so we can check for name collisions--------------#>

$VMObjects = Get-VM


function CheckVMObjects($TheVM) {

  if($VMObjects.Name -eq $TheVM) {

    Throw "VM already exists"
    Exit
  }
}

Write-Verbose -Message "Beginning deployment of VM..." -Verbose


<#----@Function:  Deploy a Server 2016 VM(s)-------------------------#>

function DeploySrv2016
{

  Write-Host "In DeploySrv2016"

  <#---------Let's import a CSV file that holds our data-----------------------#>
  $CsvData = Import-Csv -Path 'C:\Data\PSData-Prod.csv'

  $RPSIPArraySrv16 = @($CsvData.IP)
  $RPSVMNameArraySrv16 = @($CsvData.Name)
  $RPSDescriptionArraySrv16 = @($CsvData.Description)
  <#$RPSIPArraySrv16 = @('', '', '')
  $RPSVMNameArraySrv16 = @('Srv16-CI-Test', 'Srv16-CI-Test-2', 'Srv16-CI-Test-3')#>

  <#-------Let's do some kind of sanity check here----------------#>

  if($RPSVMNameArraySrv16.Length -lt 1) {
    Throw 'Error the size of the array is zero...'
    Exit
  }


  <#$RPSIPArraySrv16 = @('')
  $RPSVMNameArraySrv16 = @('Srv16-CI-Test')
  $RPSDescriptionArraySrv16 = @('Test CI build from Jenkins')#>

for($i = 0; $i -lt $RPSVMNameArraySrv16.length; $i++) {

  <#----Let's first check for a name collision------#>
  CheckVMObjects $RPSVMNameArraySrv16[$i]

  <#----If everything is good start deploying-------#>
      try {
        Get-OSCustomizationSpec $SourceCustomization | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $RPSIPArraySrv16[$i] -SubnetMask $Subnet -DefaultGateway $Gateway -Dns $RPS_DNS
        $SourceTemplate = Get-Template -Name $Srv2k16Template
        New-VM -Name $RPSVMNameArraySrv16[$i] -ResourcePool $TargetCluster -Location $RPS_Folder -Datastore $RPS_DataStore -Template $SourceTemplate -OSCustomizationSpec $SourceCustomization -Description $RPSDescriptionArraySrv16[$i] -ErrorAction Stop
        Get-NetworkAdapter -VM $RPSVMNameArraySrv16[$i] | Set-NetworkAdapter -Portgroup $ProdvDSPG -Confirm:$false
        Start-VM -VM $RPSVMNameArraySrv16[$i]
        #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
      }

      catch {

        Write-Error "Deployment of Server 2016 Failed..."
       }

   }

}


<#----@Function:  Deploy a Server 2012 R2 VM(s)-------------------------#>


function DeploySrv2012R2
{

  Write-Host "In DeploySrv2012R2"

  <#---------Let's import a CSV file that holds our data-----------------------#>
  $CsvData = Import-Csv -Path 'C:\Data\PSData-Prod.csv'

  $RPSIPArraySrv12 = @($CsvData.IP)
  $RPSVMNameArraySrv12 = @($CsvData.Name)
  $RPSDescriptionArraySrv12 = @($CsvData.Description)
  <#$RPSIPArraySrv16 = @('', '', '')
  $RPSVMNameArraySrv16 = @('Srv16-CI-Test', 'Srv16-CI-Test-2', 'Srv16-CI-Test-3')#>

  <#-------Let's do some kind of sanity check here----------------#>

  if($RPSVMNameArraySrv12.Length -lt 1) {
    Throw 'Error the size of the array is zero...'
    Exit
  }


  <#$RPSIPArraySrv12 = @('')
  $RPSVMNameArraySrv12 = @('Srv16-CI-Test')
  $RPSDescriptionArraySrv12 = @('Test CI build from Jenkins')#>

  for($i = 0; $i -lt $RPSVMNameArraySrv12.length; $i++) {

    <#----Let's first check for a name collision------#>
    CheckVMObjects $RPSVMNameArraySrv12[$i]

    <#----If everything is good start deploying-------#>
      try {
        Get-OSCustomizationSpec $SourceCustomization2012 | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $RPSIPArraySrv12[$i] -SubnetMask $Subnet -DefaultGateway $Gateway -Dns $RPS_DNS
        $SourceTemplate = Get-Template -Name $Srv2k12R2Template
        New-VM -Name $RPSVMNameArraySrv12[$i] -ResourcePool $TargetCluster -Location $RPS_Folder -Datastore $RPS_DataStore -Template $SourceTemplate -OSCustomizationSpec $SourceCustomization2012 -Description $RPSDescriptionArraySrv12[$i] -ErrorAction Stop
        Get-NetworkAdapter -VM $RPSVMNameArraySrv12[$i] | Set-NetworkAdapter -Portgroup $ProdvDSPG -Confirm:$false
        Start-VM -VM $RPSVMNameArraySrv12[$i]
        #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
       }

      catch {

        Write-Error "Deployment of Server 2012 R2 Failed..."
       }

    }

}

<#----@Function:  Deployment of centOS 7.x VM(s)-------------------------#>

function DeployLinux {

  Write-Host "In DeployLinux"

  <#---------Let's import a CSV file that holds our data-----------------------#>
  $CsvData = Import-Csv -Path 'C:\Data\PSData-Prod.csv'

  $IPArray = @($CsvData.LinuxIP.Split(','))
  $VMNameArray = @($CsvData.LinuxName.Split(','))
  $DescriptionArray = @($CsvData.LinuxDescription.Split(','))
  <#$RPSIPArraySrv16 = @('', '', '')
  $RPSVMNameArraySrv16 = @('Srv16-CI-Test', 'Srv16-CI-Test-2', 'Srv16-CI-Test-3')#>

  <#-------Let's do some kind of sanity check here----------------#>

  if($VMNameArray.Length -lt 1) {
    Throw 'Error the size of the array is zero...'
    Exit
  }

  <#$IPArray = @('', '', '')
  $VMNameArray = @("cent-automated-01", "cent-automated-02", "cent-automated-03")
  $RPS_DescriptionArray = @("Build from Jenkins", "Build from Jenkins 2", "Build from Jenkins 3")#>

for($I = 0; $I -lt $VMNameArray.length; $I++) {

  <#----Let's first check for a name collision------#>
  CheckVMObjects $VMNameArray[$I]

  <#----If everything is good start deploying-------#>
    try {
    Get-OSCustomizationSpec $SourceCustomizationLinux | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $IPArray[$I] -SubnetMask $Subnet -DefaultGateway $Gateway
    $SourceTemplate = Get-Template -Name $CentOS
    New-VM -Name $VMNameArray[$I] -ResourcePool $TargetCluster -Location $RPS_Folder -Datastore $RPS_DataStore -Template $SourceTemplate -OSCustomizationSpec $SourceCustomizationLinux -Description $DescriptionArray[$I] -ErrorAction Stop
    Get-NetworkAdapter -VM $VMNameArray[$I] | Set-NetworkAdapter -Portgroup $ProdvDSPG -Confirm:$false
    #Get-NetworkAdapter -VM $VMNameArray[$I] | Set-NetworkAdapter -NetworkName $VMNetwork -Confirm:$false
    Start-VM -VM $VMNameArray[$I]
    Write-Host "Successfully deployed"$VMNameArray.Count"Linux VM(s)"
    #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
    }

catch {

  Write-Error "Deployment of Linux Failed..."
  }

 }

}


function Deploy3Tier {


  Write-Host "In Deploy3Tier"

  <#---------Let's import a CSV file that holds our data-----------------------#>
  $CsvData = Import-Csv -Path 'C:\Data\PSData-Prod.csv'

  <#This variable controls whether or not we deploy a 2 tier or a 3 tier app 0-2 Tier, 1-3 Tier#>
  [int]$Is3Tier = 0

  <#---------SQL----------------------------------------------------------------#>
  $RPSIPArraySrv16SQL = @($CsvData.SQLIP.Split(','))
  $RPSVMNameArraySrv16SQL = @($CsvData.SQLName.Split(','))
  $RPSDescriptionArraySrv16SQL = @($CsvData.SQLDescription.Split(','))

  <#--------APP-----------------------------------------------------------------#>
  $RPSIPArraySrv16APP = @($CsvData.APPIP.Split(','))
  $RPSVMNameArraySrv16APP = @($CsvData.APPName.Split(','))
  $RPSDescriptionArraySrv16APP = @($CsvData.APPDescription.Split(','))

  <#------WEB-------------------------------------------------------------------#>
  $RPSIPArraySrv16WEB = @($CsvData.WEBIP.Split(','))
  $RPSVMNameArraySrv16WEB = @($CsvData.WEBName.Split(','))
  $RPSDescriptionArraySrv16WEB = @($CsvData.WEBDescription.Split(','))
  <#-------Let's do some kind of sanity check here----------------#>

  if($RPSVMNameArraySrv16SQL.Length -lt 1) {
    Throw 'Error the size of the array is zero...'
    Exit
  }

<#---Begin a 3Tier deployment-----------------------------------------------#>


<#----Deploy SQL--------------------------------------------------------------#>
  if($Is3Tier -eq 1) {
    for($i = 0; $i -lt $RPSVMNameArraySrv16SQL.length; $i++) {

      <#----Let's first check for a name collision------#>
      CheckVMObjects $RPSVMNameArraySrv16SQL[$i]

      <#----If everything is good start deploying-------#>
        try {
          Get-OSCustomizationSpec $SourceCustomization | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $RPSIPArraySrv16SQL[$i] -SubnetMask $Subnet -DefaultGateway $Gateway -Dns $RPS_DNS
          $SourceTemplate = Get-Template -Name $Srv2k16SQLTemplate
          New-VM -Name $RPSVMNameArraySrv16SQL[$i] -ResourcePool $TargetCluster -Location $RPS_FolderSQL -Datastore $RPS_DataStoreSQL -Template $SourceTemplate -OSCustomizationSpec $SourceCustomization -Description $RPSDescriptionArraySrv16SQL[$i] -ErrorAction Stop
          Get-NetworkAdapter -VM $RPSVMNameArraySrv16SQL[$i] | Set-NetworkAdapter -Portgroup $ProdvDSPG -Confirm:$false
          Start-VM -VM $RPSVMNameArraySrv16SQL[$i]
          Write-Host "Successfully deployed "$RPSVMNameArraySrv16SQL.Count"SQL Servers"
          #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
        }

        catch {

          Write-Error "Deployment of SQL Server Failed..."
         }

     }


     <#----Deploy APP----------------------------------------------------------#>
       for($k = 0; $k -lt $RPSVMNameArraySrv16APP.length; $k++) {

         <#----Let's first check for a name collision------#>
         CheckVMObjects $RPSVMNameArraySrv16APP[$k]

         <#----If everything is good start deploying-------#>
             try {
               Get-OSCustomizationSpec $SourceCustomization | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $RPSIPArraySrv16APP[$k] -SubnetMask $Subnet -DefaultGateway $Gateway -Dns $RPS_DNS
               $SourceTemplate = Get-Template -Name $Srv2k16Template
               New-VM -Name $RPSVMNameArraySrv16APP[$k] -ResourcePool $TargetCluster -Location $RPS_Folder -Datastore $RPS_DataStore -Template $SourceTemplate -OSCustomizationSpec $SourceCustomization -Description $RPSDescriptionArraySrv16APP[$k] -ErrorAction Stop
               Get-NetworkAdapter -VM $RPSVMNameArraySrv16APP[$k] | Set-NetworkAdapter -Portgroup $ProdvDSPG -Confirm:$false
               Start-VM -VM $RPSVMNameArraySrv16APP[$k]
               Write-Host "Successfully deployed "$RPSVMNameArraySrv16APP.Count"APP Servers"
               #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
             }

             catch {

               Write-Error "Deployment of App Server Failed..."
              }

          }

          <#----Deploy WEB--------------------------------------------------------------#>
            for($j = 0; $j -lt $RPSVMNameArraySrv16WEB.length; $j++) {

              <#----Let's first check for a name collision------#>
              CheckVMObjects $RPSVMNameArraySrv16WEB[$j]

              <#----If everything is good start deploying-------#>
                  try {
                    Get-OSCustomizationSpec $SourceCustomization | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $RPSIPArraySrv16WEB[$j] -SubnetMask $Subnet -DefaultGateway $Gateway -Dns $RPS_DNS
                    $SourceTemplate = Get-Template -Name $Srv2k16Template
                    New-VM -Name $RPSVMNameArraySrv16WEB[$j] -ResourcePool $TargetCluster -Location $RPS_Folder -Datastore $RPS_DataStore -Template $SourceTemplate -OSCustomizationSpec $SourceCustomization -Description $RPSDescriptionArraySrv16WEB[$j] -ErrorAction Stop
                    Get-NetworkAdapter -VM $RPSVMNameArraySrv16WEB[$j] | Set-NetworkAdapter -Portgroup $ProdvDSPG -Confirm:$false
                    Start-VM -VM $RPSVMNameArraySrv16WEB[$j]
                    Write-Host "Successfully deployed "$RPSVMNameArraySrv16WEB.Count"Web Servers"
                    #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
                  }

                  catch {

                    Write-Error "Deployment of Web Server Failed..."
                   }

               }

    }

    <#-----Begin 2Tier deployment SQL, WEB/APP only----------------------------------#>

    elseif($Is3Tier -eq 0) {

<#----Deploy SQL--------------------------------------------------------------#>
      for($i = 0; $i -lt $RPSVMNameArraySrv16SQL.length; $i++) {

        <#----Let's first check for a name collision------#>
        CheckVMObjects $RPSVMNameArraySrv16SQL[$i]

        <#----If everything is good start deploying-------#>
          try {
            Get-OSCustomizationSpec $SourceCustomization | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $RPSIPArraySrv16SQL[$i] -SubnetMask $Subnet -DefaultGateway $Gateway -Dns $RPS_DNS
            $SourceTemplate = Get-Template -Name $Srv2k16SQLTemplate
            New-VM -Name $RPSVMNameArraySrv16SQL[$i] -ResourcePool $TargetCluster -Location $RPS_FolderSQL -Datastore $RPS_DataStoreSQL -Template $SourceTemplate -OSCustomizationSpec $SourceCustomization -Description $RPSDescriptionArraySrv16SQL[$i] -ErrorAction Stop
            Get-NetworkAdapter -VM $RPSVMNameArraySrv16SQL[$i] | Set-NetworkAdapter -Portgroup $ProdvDSPG -Confirm:$false
            Start-VM -VM $RPSVMNameArraySrv16SQL[$i]
            Write-Host "Successfully deployed "$RPSVMNameArraySrv16SQL.Count"SQL Servers"
            #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
          }

          catch {

            Write-Error "Deployment of SQL Server Failed..."
           }

       }


       <#----Deploy APP----------------------------------------------------------#>
         for($k = 0; $k -lt $RPSVMNameArraySrv16APP.length; $k++) {

           <#----Let's first check for a name collision------#>
           CheckVMObjects $RPSVMNameArraySrv16APP[$k]

           <#----If everything is good start deploying-------#>
               try {
                 Get-OSCustomizationSpec $SourceCustomization | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $RPSIPArraySrv16APP[$k] -SubnetMask $Subnet -DefaultGateway $Gateway -Dns $RPS_DNS
                 $SourceTemplate = Get-Template -Name $Srv2k16Template
                 New-VM -Name $RPSVMNameArraySrv16APP[$k] -ResourcePool $TargetCluster -Location $RPS_Folder -Datastore $RPS_DataStore -Template $SourceTemplate -OSCustomizationSpec $SourceCustomization -Description $RPSDescriptionArraySrv16APP[$k] -ErrorAction Stop
                 Get-NetworkAdapter -VM $RPSVMNameArraySrv16APP[$k] | Set-NetworkAdapter -Portgroup $ProdvDSPG -Confirm:$false
                 Start-VM -VM $RPSVMNameArraySrv16APP[$k]
                 Write-Host "Successfully deployed "$RPSVMNameArraySrv16APP.Count"APP Servers"
                 #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
               }

               catch {

                 Write-Error "Deployment of App Server Failed..."
                }

            }

    }

  <#--------ADD CODE HERE----------------------#>
}




    switch($OSClass) {
      #$nicMapping = Get-OSCustomizationNicMapping -OSCustomizationSpec -Name $SourceCustomization | where {$_.Position -eq 1}
      1 { DeploySrv2016 }

      2 { DeploySrv2012R2 }

      3 { DeployLinux }

      4 { Deploy3Tier }

    default {
          Write-Error -Message "You did not make a correct selection..."
          Exit
    }


}




<#------------------------------------------------Legacy code to be removed------------------------------------------------------------------------------------#>

<#if($OSClass -eq 1) {
  #$nicMapping = Get-OSCustomizationNicMapping -OSCustomizationSpec -Name $SourceCustomization | where {$_.Position -eq 1}
  Get-OSCustomizationSpec $SourceCustomization | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $RPS_IPAddress -SubnetMask $Subnet -DefaultGateway $Gateway -Dns $RPS_DNS
  $SourceTemplate = Get-Template -Name $Srv2k16Template
   New-VM -Name $VMName -ResourcePool $TargetCluster -Location $RPS_Folder -Datastore $RPS_DataStore -Template $SourceTemplate -OSCustomizationSpec $SourceCustomization -Description $RPS_Description -ErrorAction Stop
   Get-NetworkAdapter -VM $VMName | Set-NetworkAdapter -NetworkName $VMNetwork -Confirm:$false
   Start-VM -VM $VMName
   #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
 }#>

 <#else {
   #$nicMapping = Get-OSCustomizationNicMapping -OSCustomizationSpec -Name $SourceCustomization | where {$_.Position -eq 1}
   Get-OSCustomizationSpec $SourceCustomization2012 | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode $RPS_IPMode -IpAddress $RPS_IPAddress -SubnetMask $Subnet -DefaultGateway $Gateway -Dns $RPS_DNS
   $SourceTemplate = Get-Template -Name $Srv2k12R2Template
    New-VM -Name $VMName -ResourcePool $TargetCluster -Location $RPS_Folder -Datastore $RPS_DataStore -Template $SourceTemplate -OSCustomizationSpec $SourceCustomization2012 -Description $RPS_Description -ErrorAction Stop
    Get-NetworkAdapter -VM $VMName | Set-NetworkAdapter -NetworkName $VMNetwork -Confirm:$false
    Start-VM -VM $VMName
    #-RunAsync Do not add to New-Vm command if you want to use Start-VM -VM $myVM command
 }#>



 #Get-OSCustomizationSpec -Name "Server2012-Customization_Automation"
 #Get-OSCustomizationSpec -Name "Server2012-Customization_Automation" | Get-OSCustomizationNicMapping

<#-----------------------------------------------End legacy block------------------------------------------------------------------------------------------------------------#>
