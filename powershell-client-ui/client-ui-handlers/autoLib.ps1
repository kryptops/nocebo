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