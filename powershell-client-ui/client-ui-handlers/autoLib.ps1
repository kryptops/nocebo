function autolib-metadata-nocebo-ui-handler()
{
    $continueLoop = $true
    $paramSet = @{"uuid"=@{"value"="null";"description"="ephemeral uuid to execute the module"}}
    while ($continueLoop) 
    {
        $handled = genericHandler $paramSet "nocebo/autolib/metadata_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "autoLib"
            $paramSet["methodName"] = "metadata"
            $paramSet["args"] = ""
            $continueLoop = $false   
        }
        elseif ($handled -eq 2)
        {
            $continueLoop = $false
        }
        elseif ($handled -eq 3)
        {
            $paramSet["uuid"] = "retr"
            $continueLoop = $false
        }
        else
        {
            $paramSet = $handled
        }
    }
    return $paramSet
}

function autolib-replicate-nocebo-ui-handler()
{
    $continueLoop = $true
    $paramSet = @{"uuid"="null"}
    while ($continueLoop) 
    {
        $handled = genericHandler $paramSet "nocebo/autolib/replicate_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "autoLib"
            $paramSet["methodName"] = "replicate"
            $paramSet["args"] = ""
            $continueLoop = $false
        }
        elseif ($handled -eq 2)
        {
            continue
        }
        elseif ($handled -eq 3)
        {
            $paramSet["uuid"] = "retr"
            $continueLoop = $false
        }
        else
        {
            $paramSet = $handled
        }
    }

    return $paramSet
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