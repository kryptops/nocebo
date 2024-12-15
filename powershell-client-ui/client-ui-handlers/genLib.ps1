function genlib-clipper-nocebo-ui-handler()
{
    $continueLoop = $true
    $paramSet = @{"uuid"="null";"duration"="null"}
    while ($continueLoop) 
    {
    $handled = genericHandler $paramSet "nocebo/autolib/clipper_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "genLib"
            $paramSet["methodName"] = "clipper"
            $paramSet["args"] = "duration,$($paramSet['duration'])"
            $paramSet.remove("duration")
            
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

function genlib-snapper-nocebo-ui-handler()
{
    $continueLoop = $true
    $paramSet = @{"uuid"="null";"duration"="null";"frequency"="null"}
    while ($continueLoop) 
    {
    $handled = genericHandler $paramSet "nocebo/autolib/snapper_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "genLib"
            $paramSet["methodName"] = "snapper"
            $paramSet["args"] = "duration,$($paramSet['duration']),frequency,$($paramSet['frequency'])"
            $paramSet.remove("duration")
            $paramSet.remove("frequency")
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

function genlib-upload-nocebo-ui-handler()
{
    $continueLoop = $true
    $paramSet = @{"uuid"="null";"data"="null";"location"="null"}
    while ($continueLoop) 
    {
    $handled = genericHandler $paramSet "nocebo/autolib/upload_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "genLib"
            $paramSet["methodName"] = "upload"
            $paramSet["args"] = "data,$($paramSet['data']),location,$($paramSet['location'])"
            $paramSet.remove("data")
            $paramSet.remove("location")
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
            #$paramSet = $handled
            #check if path
            if ($(test-path $handled["data"]))
            {
                $uploadBytes = [io.file]::ReadAllBytes($handled[$data])
                $handled["data"] = [system.convert]::tobase64string($uploadBytes)
                $paramSet = $handled
            }
            else
            {
                $paramSet = $handled
            }
        }
    }
    return $paramSet
}

function genlib-download-nocebo-ui-handler()
{
    $continueLoop = $true
    $paramSet = @{"uuid"="null";"location"="null"}
    while ($continueLoop) 
    {
    $handled = genericHandler $paramSet "nocebo/autolib/download_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "autoLib"
            $paramSet["methodName"] = "replicate"
            $paramSet["args"] = "location,$($paramSet['location'])"
            $paramSet.remove("location")
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

function genlib-process-nocebo-ui-handler()
{
    $continueLoop = $true
    $paramSet = @{"uuid"="null";"command"="null";"arguments"="null"}
    while ($continueLoop) 
    {
    $handled = genericHandler $paramSet "nocebo/autolib/process_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "genLib"
            $paramSet["methodName"] = "process"
            $paramSet["args"] = "command,$($paramSet['command']),arguments,$($paramSet['arguments'])"
            $paramSet.remove("command")
            $paramSet.remove("arguments")
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
}

function genericHandler($params, $prompt)
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
                
            write-host -foregroundcolor yellow "    : $p"
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
        $params[$paramTuple[0]] = $paramTuple[1]
        return $params   
    }
}