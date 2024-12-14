function autolib-metadata-nocebo-ui-handler()
{
    $continueLoop = $true
    $paramSet = @{"uuid"="null"}
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

function genericHandler($paramSet, $prompt)
{
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
        foreach ($p in $paramSet.Keys)
        {
                
            write-host -foregroundcolor yellow "    : $p"
        }
        write-host ""
        return 0
    }
    elseif ($userInput.ToLower() -eq "back")
    {
        return 3
    }
    elseif ($paramSet.keys -notcontains $userInput.ToLower().split("=")[0])
    {
        write-host -ForegroundColor yellow "!!! Invalid parameter"
        return 2
    }
    else
    {
        $paramTuple = $userInput.ToLower().split("=")
        $parmSet[$paramTuple[0]] = $paramTuple[1]
        return $paramSet   
    }
}