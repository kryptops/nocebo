function modLogHelper($apiAddr)
{
    $continueLoop = $true
        $httpOut = httpsHandler "GET" @{"nClient-key"=$plaintextNApiKey} "https://$apiAddr/log"
        $httpOut.content

}

function genericHandler($description, $params, $prompt)
{
    $paramTuple = ""   
    write-host -NoNewline -ForegroundColor darkmagenta $prompt
    $userInput = Read-Host 
    write-host ""
    if ($userInput.ToLower() -eq "task")
    {
        write-host -foregroundcolor yellow ">>> Attempting to task nocebo api"
        return 1
    }
    elseif ($userInput.ToLower() -eq "options")
    {
        write-host ""
        foreach ($p in $params.Keys)
        {
                
            write-host -foregroundcolor yellow "    : $p : $(($params[$p])["description"])"
        }
        write-host ""
        return 0
    }
    elseif ($userInput.ToLower() -eq "description")
    {
        write-host ""
        foreach ($p in $params.Keys)
        {
                
            write-host -foregroundcolor yellow "    $description"
        }
        write-host ""
        return 0
    }
    elseif ($userInput.ToLower() -eq "back")
    {
        return 3
    }
    elseif ($params.keys -notcontains $userInput.ToLower().split("=")[0])
    {
        write-host -ForegroundColor yellow "!!! Invalid parameter"
        return 2
    }
    else
    {
        $paramTuple = $userInput.ToLower().split("=")
        ($params[$paramTuple[0]])["value"] = $paramTuple[1]
        return $params   
    }
}