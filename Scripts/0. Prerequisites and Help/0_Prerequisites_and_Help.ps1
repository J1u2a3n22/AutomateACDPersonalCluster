class Verifier {
    [string[]] $dnsSuffixListEastern
    [string[]] $dnsSuffixListWestern

    Verifier(){
        #Set-ExecutionPolicy Unrestricted
        Install-Module VSSetup -Scope CurrentUser
        $this.dnsSuffixListWestern="ucn.net","inucn.com","nw.inucn.com","incmp.com","ineur.eu","in.lab","blfdev.lab","i-link.net","adfs.lab","fed.lab","adfs.corp","icc.lab","uptivity.com","digitalvoicelogging.com","nice.com","callcopy.com","Ucndmz.net","Ucnlabdmz.com","ICCorplab.com","inlab.com","dradev.lab","infrh.com","nw.in.lab"
        $this.dnsSuffixListEastern="nice.com","adrembi.com","na.nice.com","eu.nice.com","ds.searchspace.com","e-glue.com","ucn.net","in.lab","inucn.com","ineur.eu","dradev.lab","link.net","blfdev.lab","ucnlabext.com","incmp.com"

    }
    
    [PSObject] VerifyMSDNVersion()
    {
        $isCorrect=$false
        $msdnVersion = ''
        $msdnVersion = (Get-VSSetupInstance -All | Select-VSSetupInstance -Require 'Microsoft.VisualStudio.Workload.ManagedDesktop' -Latest | Select-Object DisplayName).DisplayName
        if($msdnVersion.Contains("Professional"))
        {
            $isCorrect=$true
        }
        return [PSObject]@{
            value1=[bool]$isCorrect
            value2=[string]$msdnVersion
        }
    }

    [PSObject] VerifyVPN()
    {
        $isCorrect=$false
        $globalProtect=Get-ChildItem -Path 'HKLM:\SOFTWARE\Palo Alto Networks' | Select-Object -ExpandProperty Name #Display all registry keys related to Palo Alto Networks, which may provide additional information about the VPN solution installed on the computer.
        $vpnCompanyName=$globalProtect.Split("\")[2] + " " + $globalProtect.Split("\")[3]
        if($vpnCompanyName.Contains("Palo Alto Networks") -and $vpnCompanyName.Contains("GlobalProtect"))
        {
            $isCorrect=$true
        }
        return [PSObject]@{
            value1=[bool]$isCorrect
            value2=[string]$vpnCompanyName
        }
    }


    [PSObject] VerifyVPNStatus()
    {
        $isCorrect=$false
        $detailsConnection='You are not connected to PANGP Virtual Ethernet Adapter Secure'
        $ethernetConnections=(Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -ExpandProperty InterfaceDescription)
        if($ethernetConnections.Contains("PANGP Virtual Ethernet Adapter Secure")){
            $isCorrect=$true
            $detailsConnection='You are connected to PANGP Virtual Ethernet Adapter Secure'
        }
        return [PSObject]@{
            value1=[bool]$isCorrect
            value2=[string]$detailsConnection
        }
    }





    [PSObject] VerifyWindowsLocalAdministrativeRight()
    {
        $answer='You do not have Windows Local Administrative Right'
        $AdministratorPermissions=([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if($AdministratorPermissions -eq $true){
            $answer='You have WindowsLocalAdministrativeRight'
        }
        return [PSObject]@{
            value1=[bool]$AdministratorPermissions
            value2=[string]$answer
        }
    }

    [PSObject] VerifyAccessNetworkDrivePaths()
    {
        $MSDN=Test-Path '\\corpfs01\MSDN\'
        $latest= Test-Path '\\corpfs02\Latest\'
        $answer=$MSDN -and $latest
        $accessNetworkDrivePaths = 'You do not have access to \\corpfs01\MSDN\'
        if ($MSDN) {
            $accessNetworkDrivePaths = 'You have access to \\corpfs01\MSDN\'
        }
        if ($latest) {
            $accessNetworkDrivePaths += ' and You have access to \\corpfs02\Latest\'
        }
        else {
            $accessNetworkDrivePaths += ' and You do not have access to \\corpfs02\Latest\'
        }
        return [PSObject]@{
            value1=[bool]$answer
            value2=[string]$accessNetworkDrivePaths
        }
    }


    [PSObject]  VerifyDNSSuffix([string]$location)
    {
        $isCorrect=$false
        $suffixList = (Get-DnsClientGlobalSetting).SuffixSearchList
        $suffixListString = [string]::Join(",", $suffixList)
        switch($location.ToLower()){
            "western"{
                $dnsSuffixListWesternString =[string]::Join(",", $this.dnsSuffixListWestern) 
                if($suffixListString -eq $dnsSuffixListWesternString)
                {
                    $isCorrect=$true
                }
            }
            "eastern"{
                $dnsSuffixListWesternString =[string]::Join(",", $this.dnsSuffixListEastern) 
                if($suffixListString -eq $dnsSuffixListWesternString){
                    $isCorrect=$true
                }
            }
        }
        return [PSObject]@{
            value1=[bool]$isCorrect
            value2=[string]'Your DNS access are: '+ $suffixListString
        }
    }

    [pscustomobject]VerifyAllPreRequisites()
    {
        $VpnDetails=$this.VerifyVPN()
        $VpnStatus=$this.VerifyVPNStatus()
        $WindowsLocalAdministrativeRightDetails=$this.VerifyWindowsLocalAdministrativeRight()
        $NetworkDrivePathsDetails=$this.VerifyAccessNetworkDrivePaths()
        $DnsSuffixDetails=$this.VerifyDNSSuffix("western")
        $results=@(
            [pscustomobject]@{AccessName  = "Global protect VPN" ; Access =$VpnDetails.value1; details=$VpnDetails.value2},
            [pscustomobject]@{AccessName  = "Global protect VPN status" ; Access =$VpnStatus.value1; details=$VpnStatus.value2},
            [pscustomobject]@{AccessName  = "Windows local administrative rights" ; Access =$WindowsLocalAdministrativeRightDetails.value1; Details=$WindowsLocalAdministrativeRightDetails.value2},
            [pscustomobject]@{AccessName  = "Access to shared network drive paths" ; Access =$NetworkDrivePathsDetails.value1; Details=$NetworkDrivePathsDetails.value2},
            [pscustomobject]@{AccessName  = "DNS suffixes" ; Access =$DnsSuffixDetails.value1; Details=$DnsSuffixDetails.value2}
        )
        return $results | Format-Table -Wrap -Property AccessName, Access, Details
    }


}


$verifier= [Verifier]::new()
$results=$verifier.VerifyAllPreRequisites()
Write-Output $results 


