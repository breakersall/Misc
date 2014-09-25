<#
.SYNOPSIS

    Sends spoofed emails to all mx records from all domains (a lot of emails). This is a comprehensive spoof and relay assessment script. No warranties.

    Function: Invoke-SpoofEmail
    Author: Matt Kelly, @breakersall
    License: BSD 3-Clause
    Required Dependencies: PSv2
    Version: 1.0
 
.DESCRIPTION

    Takes a domain list, enumerates all mx records, sends a legitimate to and from, relay from legitimate, and invalid from all domains for all mx records. Yes it is a lot of emails, but turns out disabling this in Exchange is hard!

.EXAMPLE

    PS C:\>Invoke-SpoofEmail -ToClientAddress CLIENTAddress1@CLIENTDOMAIN.com -FromClientAddress CLIENTAddress2@CLIENTDOMAIN.com -Domains domain-list.txt -ToYourEmailAddress mattkelly123@gmail.com
	
#>
Function Invoke-SpoofEmail
{
	[CmdletBinding()]
    Param 
	(
		[Parameter(Mandatory=$true,
		HelpMessage='Provide a text file of relavent client domains, example: C:\temp\client-domains.txt')]
		[string]$Domains,
		
		[Parameter(Mandatory=$true,
		HelpMessage='Provide the client  email address that will be used for sending to (inform client of pending emails prior to sending)')]
		[string]$ToClientAddress,
		
		[Parameter(Mandatory=$true,
		HelpMessage='Provide your email address for relay testing (if you get the email they allow relay in the stone ages)')]
		[string]$ToYourEmailAddress,
		
		[Parameter(Mandatory=$true,
		HelpMessage='Provide a legitimate client internal email address that is not the sender (for spoofing tests from valid emails)')]
		[string]$FromClientAddress,
		
		[Parameter(Mandatory=$true,
		HelpMessage='Optionally provide a body message')]
		[string]$Body = "Please forword this email to your pentester"
	)

		#####***Following MX record lookup code borrowed code from:http://serverfault.com/questions/164508/anyone-have-a-powershell-script-to-look-up-the-mx-record-for-a-domain***#####
		function Get-DnsAddressList
		{
			param(
				[parameter(Mandatory=$true)][Alias("Host")]
				  [string]$HostName)

			try {
				return [System.Net.Dns]::GetHostEntry($HostName).AddressList
			}
			catch [System.Net.Sockets.SocketException] {
				if ($_.Exception.ErrorCode -ne 11001) {
					throw $_
				}
				return = @()
			}
		}

function Get-DnsMXQuery
{
    param(
        [parameter(Mandatory=$true)]
          [string]$DomainName)
 
    if (-not $Script:global_dnsquery) {
        $Private:SourceCS = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
 
namespace PM.Dns {
  public class MXQuery {
    [DllImport("dnsapi", EntryPoint="DnsQuery_W", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
    private static extern int DnsQuery(
        [MarshalAs(UnmanagedType.VBByRefStr)]
        ref string pszName,
        ushort     wType,
        uint       options,
        IntPtr     aipServers,
        ref IntPtr ppQueryResults,
        IntPtr pReserved);
 
    [DllImport("dnsapi", CharSet=CharSet.Auto, SetLastError=true)]
    private static extern void DnsRecordListFree(IntPtr pRecordList, int FreeType);
 
    public static string[] Resolve(string domain)
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            throw new NotSupportedException();
 
       List<string> list = new List<string>();
 
        IntPtr ptr1 = IntPtr.Zero;
        IntPtr ptr2 = IntPtr.Zero;
        int num1 = DnsQuery(ref domain, 15, 0, IntPtr.Zero, ref ptr1, IntPtr.Zero);
        if (num1 != 0)
            throw new Win32Exception(num1);
        try {
            MXRecord recMx;
            for (ptr2 = ptr1; !ptr2.Equals(IntPtr.Zero); ptr2 = recMx.pNext) {
                recMx = (MXRecord)Marshal.PtrToStructure(ptr2, typeof(MXRecord));
                if (recMx.wType == 15)
                   list.Add(Marshal.PtrToStringAuto(recMx.pNameExchange));
            }
        }
        finally {
            DnsRecordListFree(ptr1, 0);
        }
 
        return list.ToArray();
    }
 
    [StructLayout(LayoutKind.Sequential)]
    private struct MXRecord
    {
        public IntPtr pNext;
        public string pName;
        public short  wType;
        public short  wDataLength;
        public int    flags;
        public int    dwTtl;
        public int    dwReserved;
        public IntPtr pNameExchange;
        public short  wPreference;
        public short  Pad;
    }
  }
}
'@

				Add-Type -TypeDefinition $Private:SourceCS -ErrorAction Stop
				$Script:global_dnsquery = $true
			}
			
			[PM.Dns.MXQuery]::Resolve($DomainName) | % {
				$rec = New-Object PSObject
				Add-Member -InputObject $rec -MemberType NoteProperty -Name "Host"        -Value $_
				Add-Member -InputObject $rec -MemberType NoteProperty -Name "AddressList" -Value $(Get-DnsAddressList $_)
				$rec.AddressList.IpAddressToString
			}
			
		}
		#####End Borrowed Code#####
		$LogString = "mail-spoofing.log"
		$DomainsToTest = Get-Content $Domains
		$ClientMXRecords =@()
		foreach ($Domain in $DomainsToTest)
		{
			try
			{
				[array]$MXArray = Get-DnsMXQuery -DomainName "$Domain"
				Write-Host "Found This many MX Records for $Domain :" $MXArray.Count
				"The following MX records are associated with $Domain $MXArray" | Out-File -Append -Encoding ascii "$LogString"
				if ($ClientMXRecords -notcontains $MXArray)
				{
					$ClientMXRecords = $ClientMXRecords + $MXArray
				}
			}
			catch
			{
			}

		}
		foreach ($ClientMXRecord in $ClientMXRecords)
		{
			#ValidChecks
			Send-MailMessage -from "$FromClientAddress" -to "$ToClientAddress" -subject "SPOOF TEST: This is a valid spoof test for $ClientMXRecord" -body "$Body" -smtpServer "$ClientMXRecord" -DeliveryNotificationOption OnFailure
			"Valid parameters, FROM: $FromClientAddress TO: $ToClientAddress Subject: SPOOF TEST: This is a valid spoof test for $ClientMXRecord Body: $Body" | Out-File -Append -Encoding ascii "$LogString"
			#RelayChecks
			Send-MailMessage -from "$ToClientAddress" -to "$ToYourEmailAddress" -subject "SPOOF TEST: Relay Valid Address on $ClientMXRecord" -body "$Body" -smtpServer "$ClientMXRecord" -DeliveryNotificationOption OnFailure
			"Relay valid parameters, FROM: $ToClientAddress TO: $ToYourEmailAddress Subject: SPOOF TEST: Relay InValid Address on $ClientMXRecord" | Out-File -Append -Encoding ascii "$LogString"

			foreach ($Domain in $DomainsToTest)
			{
				#InvalidChecks

				$FromInvalid = "INVALIDAddress-TEST@" + "$Domain"
				Send-MailMessage -from "$FromInvalid" -to "$ToClientAddress" -subject "SPOOF TEST: This is a invalid spoof test for $ClientMXRecord" -body "$Body" -smtpServer "$ClientMXRecord" -DeliveryNotificationOption OnFailure
				"InValid parameters, FROM: $FromInvalid TO: $ToClientAddress Subject: SPOOF TEST: This is a invalid spoof test for $ClientMXRecord" | Out-File -Append -Encoding ascii "$LogString"
				$FromInvalidRelay = "INVALIDRelayAddress-TEST@" + "$Domain"
				Send-MailMessage -from "$FromInvalidRelay" -to "$ToYourEmailAddress" -subject "SPOOF TEST: Relay InValid Address on $ClientMXRecord" -body "$Body" -smtpServer "$ClientMXRecord" -DeliveryNotificationOption OnFailure
				"Relay InValid parameters, FROM: $FromClientAddress TO: $ToClientAddress Subject: Relay InValid Address on $ClientMXRecord" | Out-File -Append -Encoding ascii "$LogString"
			}
			Write-Host ""
			Write-Host ""
			Write-Host ""
			Write-Host "*************************"
		}
}