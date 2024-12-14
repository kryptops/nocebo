function autolib-metadata-nocebo-ui-handler()
{
    $continueLoop = $true
    while ($continueLoop) 
    {
        write-host -NoNewline -ForegroundColor darkmagenta "nocebo/autolib/metadata_ "
        $userInput = Read-Host 
        write-host ""
        if ($userInput -eq "task")
        {
            write-host ">>> Attempting to task nocebo api"
            return
        }
        else
        {

        }
    }
}

function autolib-replicate-nocebo-ui-handler()
{
    $continueLoop = $true
    while ($continueLoop) 
    {
        write-host -NoNewline -ForegroundColor darkmagenta "nocebo/autolib/replicate_ "
        $userInput = Read-Host 
        write-host ""
    }
}
