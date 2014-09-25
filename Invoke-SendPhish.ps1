<#
.SYNOPSIS

    Invoke-SendPhish sends a spoofed email message from a csv input with an attachment and a delay possibility. Requires Powershell 2.0. May generate error if only 1 email is in CSV due to my bad status bar math, all is working fine...

    Function: Invoke-SendPhish
    Author: Matt Kelly, @BreakersAll
    License: BSD 3-Clause
    Required Dependencies: PSv2
    Version: 1.0
 
.DESCRIPTION

    Invoke-SendPhish sends a spoofed email message from a csv input with an attachment and a delay possibility.

.PARAMETER CSVInput

	Specify an input file containing parameters to find and replace in boyd and send email, first three MUST BE firstname,lastname,emailaddress, optionally after that you can have up to three additional ones in one line (6 total): (optional)parameter1, (optional)parameter2,(optional)parameter3, example: C:\temp.csv.

.PARAMETER SMTPServer

	Optionally specify an SMTP Server.
	
.PARAMETER EmailBody

	Supply the email body in HTML format, the following parameters can be used to replace: FNAME,LNAME,PARAMETER1,PARAMETER2,PARAMETER3.

.PARAMETER Subject

	Supply the email subject.

.PARAMETER FromAddress

	Optionally supply the from address, be mindful of spaces, defaults to IT HelpDesk ITHelpDesk@domain with a ton of spaces to obscure real sender address.

.PARAMETER Attachment

	Optionally supply an attachment to use, example -Attachment C:\MacroPowershellWordDoc.doc.

.PARAMETER Delay

	Optionally specify a static delay between emails.

.PARAMETER DelayRandom

	Optionally specify a random delay value with the value being the maximum, picks random between 1 and that number after each email.
	
.EXAMPLE

    PS C:\>Invoke-SendPhish -CSVInput Input.csv -EmailBody email-body.txt -Subject "PhishingEmail" -FromAddress "HelpDesk                                                                                                                                                                                                                                                                                                                                      . <IT-Helpdesk@domain.com>" -SMTPServer 1.1.1.1
.EXAMPLE

    PS C:\>Invoke-SendPhish -CSVInput Input.csv -EmailBody email-body.txt -Subject "TEST EMAIL" -Delay 180

.EXAMPLE

    PS C:\>Invoke-SendPhish -CSVInput Input.csv -EmailBody email-body.txt -Subject "TEST EMAIL" -DelayRandom 180

#>
Function Invoke-SendPhish
{
	[CmdletBinding()]
    Param 
	(
		[Parameter(Mandatory=$true,
		HelpMessage='Provide the CSV in firstname,lastname,ToEmailAddress (example: matt,kelly,mattkelly@gmail.com')]
		[ValidateScript({Test-Path $_})]
		[string]$CSVInput,
		
		[Parameter(Mandatory=$true,
		HelpMessage='Provide the HTML body email to send, use KEYWORDS FNAME, LNAME to replace contents')]
		[ValidateScript({Test-Path $_})]
		[string]$EmailBody,
		
		[Parameter(Mandatory=$true,
		HelpMessage='Provide the email subject, example: -Subject "Definitely Not a phishing email"')]
		[string]$Subject,
		
		[Parameter(Mandatory=$false,
		HelpMessage='Optionally specify the from address, remember lots of spaces to fool Outlook, defaults to a stealthy one from ITHelpDesk@domain.com')]
		[string]$FromAddress = "IT HELPDESK                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               . <ITHelpDesk@domain.com>",
		
		[Parameter(Mandatory=$false,
		HelpMessage='Optionally specify an email attachment')]
		[ValidateScript({Test-Path $_})]
		[int]$Attachment,
		
		[Parameter(Mandatory=$true,
		HelpMessage='Specify the SMTP Server')]
		[string]$SMTPServer,
		
		[Parameter(Mandatory=$false,
		HelpMessage='Sets a random delay with a user specified maximum number in seconds')]
		[int]$DelayRandom,
		
		[Parameter(Mandatory=$false,
		HelpMessage='Optionally delay the send (specify in seconds)')]
		[int]$Delay
	)
	
	$ItemsToSend = Import-Csv $CSVInput -Header @("Firstname","Lastname","Email","Param1","Param2","Param3")
	Write-Host "Items to send is currently equal to: $ItemsToSend"
	$SendCount = $ItemsToSend.Count
	if ($SendCount -eq 0)
	{
		$SendCount++
	}
    $Count = 0
	ForEach ($line in $ItemsToSend)
	{
		$Body = Get-Content $EmailBody
		$Count++
		If ($Count/100 -lt 1 -or $Count -eq 1) 
		{
           Write-Progress -Activity "Sending Phishing Email" `
               -Status "Processing Line $Count of $SendCount Sending to $line" `
               -PercentComplete ($Count/$SendCount*100)
        }
		
		$Body = $Body.Replace("FNAME",$line.Firstname)
		$Body = $Body.Replace("LNAME",$line.Lastname)
		if ($line.Param1) {$Body = $Body.Replace("PARAMETER1",$line.Param1)}
		if ($line.Param2) {$Body = $Body.Replace("PARAMETER2",$line.Param2)}
		if ($line.Param3) {$Body = $Body.Replace("PARAMETER3",$line.Param3)}
		if ($Attachment)
		{
			Send-MailMessage -from "$FromAddress" -to $line.Email -subject "$Subject" -body "$Body" -smtpServer "$SMTPServer" -DeliveryNotificationOption OnFailure -BodyAsHtml -Attachment $Attachment
		}
		else
		{
			Send-MailMessage -from "$FromAddress" -to $line.Email -subject "$Subject" -body "$Body" -smtpServer "$SMTPServer" -DeliveryNotificationOption OnFailure -BodyAsHtml
		}
		if ($DelayRandom)
		{
			$RandomDelay = Get-Random -Maximum $DelayRandom -Minimum 1
			Write-Host "Sleeping $RandomDelay seconds."
			Sleep -Seconds $RandomDelay
		}
		elseif ($Delay)
		{
			Write-Host "Sleeping $Delay seconds."
			Sleep -Seconds $Delay
		}
	}
	If ($Count -eq $SendCount) 
	{
            Write-Progress -Activity "Parsing Email Phish Send CSV File" `
               -Status "Processing Line $Count of $SendCount" `
               -PercentComplete ($Count/$SendCount*100) `
               -Completed
    }
}