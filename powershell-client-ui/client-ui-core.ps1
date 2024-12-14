﻿
$global:uiHandlerDir = ".\client-ui-handlers\"
$ErrorActionPreference= 'silentlycontinue'

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


function httpsHandler($httpRequestMethod, $httpHeaderDict, $httpUrl, $httpPostData)
{
    if ($httpRequestMethod -eq "POST")
    {
        Invoke-WebRequest -headers $httpHeaderDict -uri $httpUrl -Method $httpRequestMethod -body $httpPostData
    }
    else
    {
        Invoke-WebRequest -headers $httpHeaderDict -uri $httpUrl -Method $httpRequestMethod
    }
}


function mainLoop()
{
    write-host -foregroundcolor DarkMagenta @"

███╗   ██╗ ██████╗  ██████╗███████╗██████╗  ██████╗ 
████╗  ██║██╔═══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗
██╔██╗ ██║██║   ██║██║     █████╗  ██████╔╝██║   ██║
██║╚██╗██║██║   ██║██║     ██╔══╝  ██╔══██╗██║   ██║
██║ ╚████║╚██████╔╝╚██████╗███████╗██████╔╝╚██████╔╝
╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚══════╝╚═════╝  ╚═════╝ 
[By Kryptops]
  
                                                
"@

    write-host -ForegroundColor yellow -NoNewline "Enter your nocebo api key:"
    $nApiKey = read-host -AsSecureString
    $plaintextNApiKey = [Net.NetworkCredential]::new('', $nApiKey).Password
    write-host ""
    Get-ChildItem ($uiHandlerDir) | ForEach-Object {. (Join-Path $uiHandlerDir $_.Name)} | Out-Null
    
    write-host -ForegroundColor yellow "[                Type 'exit' or 'quit' to exit the ui                 ]"
    write-host -ForegroundColor yellow "[ Type the name of a module followed by 'options' to view its options ]"
    write-host -ForegroundColor yellow "[       Type 'modules' to view a list of loaded module handlers       ]"
    write-host -ForegroundColor yellow "[         Modules can be executed by typing the module's name         ]"
    write-host ""
    
    $continueLoop = $true

    while ($continueLoop) {
    # Prompt the user for input
    write-host -NoNewline -ForegroundColor darkmagenta "nocebo_ "
    $userInput = Read-Host 
    write-host ""

    # Check if the user wants to quit
    if ("exit" -contains $userInput.ToLower() -or "quit" -contains $userInput.ToLower()) 
    {
        $continueLoop = $false
    }
    elseif ($userInput.ToLower() -eq "modules")
    {
        gcm ("*autolib*")
        $loadedMods = (gcm "*nocebo-ui-handler").name
        write-host -ForegroundColor Yellow  ">>> The following modules have candidate client handlers"
    
        foreach ($m in $loadedMods)
        {
            $v = $($m.split("-")[0..1]) -join "-"
            write-host -ForegroundColor Gray "    : $v"
        }
        write-host ""
    }
    elseif ($userInput.ToLower() -eq "")
    {
        continue
    }
    else
    {
        
        if ((gcm "*$($userinput.ToLower())-nocebo-ui-handler*").name -ne $null)
        {
            write-host -ForegroundColor yellow ">>> Type 'back' to return to the main console"
            write-host -ForegroundColor yellow ">>> Type 'task' to send a task for this module to the server"
            
            $methodAndArgs = & "$($userinput.ToLower())-nocebo-ui-handler"
            try
            {
                httpsHandler "POST" @{"nClientKey"=$plaintextNApiKey} $methodAndArgs["params"]
            }
            catch
            {
                write-host -ForegroundColor yellow "!!! Failed to send request to server, most likely due to authentication."
            }
        }
        else
        {
            write-host -ForegroundColor yellow "!!! Unknown command. Please type one of the system commands or specify a module to run."
        }
    }
}


}

function start-noceboClientUI()
{

    mainLoop
}