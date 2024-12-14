function autolib-metadata-nocebo-ui-handler()
{
    $continueLoop = $true
    while ($continueLoop) 
    {
        write-host -NoNewline -ForegroundColor darkmagenta "nocebo/autolib/metadata_ "
        $userInput = Read-Host 
        write-host ""
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