
Write-Output "---------------- Export/Import Active Directory Users ----------------"

for ($i = 0; $true; $i++) {
    
    Write-Output "-Export (1)"
    Write-Output "-Imoport (2)"
    Write-Output "-Exit (3)"

    $Menu = Read-Host -Prompt "Select one of the above obtions by putting the number!(1/2/3)"

    if ($Menu -eq 1) {
        Write-Output "-------- EXPORT USERS ----------"
        $num = Read-Host -Prompt "How many properties you'll use ?"
        for ([int]$i = 0; $i -lt $num; $i++) {        
            [string[]]$Word += Read-Host        
        }
        $file = Read-Host -Prompt "Insert the file name "
        
        Get-ADUser -Filter * -Properties $Word  | Select-Object $Word | Export-csv $file
    }
    elseif ($Menu -eq 2) {
        
        $domain = -join("@",(Get-ADForest).Name)
        $UserOU = (Get-ADDomain).DomainControllersContainer
        $file = Read-Host "Where is the csv file with the users? (PATH)"
        $NewUserList = Import-Csv $file -Delimiter ";"
        


    }
    elseif ($Menu -eq 3) {
        break
    }
    else {
        Write-Output "You are retarded or what? You just have to choose between 1 or 2!!! TRY AGAIN"

    }
    


}