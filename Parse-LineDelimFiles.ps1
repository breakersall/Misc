<#
	.Description
	This script parses multiple line deliminated files into a CSV.

	Function: Parse-Files
	Author: Matt Kelly, @breakersall
	Required Dependencies: PSv3

	.PARAMETER Directory

	Specify the directory to make into CSV.

	.PARAMETER Extension

	Specify the extension to parse into a CSV, example _local_admins.txt.
	
	.PARAMETER Extension

	Specify the extension to parse into a CSV, example _local_admins.txt.

	.PARAMETER Output

	Specify the output file, example -Output local_admins.csv.
#>
[CmdletBinding()]
Param(
		[Parameter(Mandatory=$false,
		HelpMessage='Specify the directory to make into CSV, example: C:\Temp')]
		[ValidateScript({Test-Path $_})]
		[string]$Directory,

		[Parameter(Mandatory=$false,
		HelpMessage='Specify the extension to parse into a CSV, example _local_admins.txt')]
		[string]$Extension,

		[Parameter(Mandatory=$false,
		HelpMessage='Specify the output file, example -Output local_admins.csv')]
		[string]$Output
	)

$Files = Get-ChildItem $Directory\*$Extension | Select-Object -ExpandProperty Name
	
foreach ($File in $Files) 
{
	cd $Directory
	$admins = get-content $Directory\$File
	[string]$line2
	$Compname = $File.replace("$Extension","")
	foreach ($admin in $admins)
	{
		$line = $Compname + "," + $admin
		$line | Out-File -Encoding ASCII -Append $Output
	}
	
}
