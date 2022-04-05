#Pt.4 Automatisation OU Active Directory
# Author Jordi Forés Garcia

# Functions 

function getInfo([Object] $name){
    foreach ($Comptes in $name){
        Write-Host $Comptes.Name 
    }
}

function getInfoAfter([Object] $name){
    
        for ($i =0; $i-lt ($name).Count;$i++){
            if ($i -eq ((($name).Count)-1)){
                Write-Host $name[$i].Name -ForegroundColor Green
            }else{
                Write-Host $name[$i].Name
            }
        }
}

# This fuction checks if string is null or empty and object exist or not.
function isValid($param){    
    if ([string]::IsNullOrEmpty($param[1])){        
        return $False
        
    }elseif($param[2] -eq $true){
        if($param[0].Name -contains $param[1]){            
            return $False
        }else{            
            return $true
        }
    }else{
        if($param[0].Name -contains $param[1]){            
            return $true
        }else{
            return $false
        }                
    }
}

$title = "
     _        _   _             ____  _               _                     __  __                                   
    / \   ___| |_(_)_   _____  |  _ \(_)_ __ ___  ___| |_ ___  _ __ _   _  |  \/  | __ _ _ __   __ _  __ _  ___ _ __ 
   / _ \ / __| __| \ \ / / _ \ | | | | | '__/ _ \/ __| __/ _ \| '__| | | | | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|
  / ___ \ (__| |_| |\ V /  __/ | |_| | | | |  __/ (__| || (_) | |  | |_| | | |  | | (_| | | | | (_| | (_| |  __/ |   
 /_/   \_\___|\__|_| \_/ \___| |____/|_|_|  \___|\___|\__\___/|_|   \__, | |_|  |_|\__,_|_| |_|\__,_|\__, |\___|_|   
                                                                    |___/                            |___/           

"

$Author ="
     _         _   _                           _____ _     _            _     
    / \  _   _| |_| |__   ___  _ __   _  __  _|_   _| |__ | | __ _  ___| |__  
   / _ \| | | | __| '_ \ / _ \| '__| (_) \ \/ / | | | '_ \| |/ _`  |/ __| '_ \ 
  / ___ \ |_| | |_| | | | (_) | |     _   >  <  | | | | | | | (_| | (__| | | |
 /_/   \_\__,_|\__|_| |_|\___/|_|    (_) /_/\_\ |_| |_| |_|_|\__,_|\___|_| |_|
                                                                                                                      
Twitch : twitch.tv/xthalach Git: github.com/xthalach

!Thx for using my script!
 "

#First we test if the user have the Domain installed.
if(((Get-ADForest).Name).Equals((Get-ADForest).Name)){

    Write-Output "[*] Checking Domain Forest Name"
    $ForestName = (Get-ADForest).Name
    Write-Output "[*] The Forest Name: $ForestName"    
    Start-Sleep 5
    for ($i = 0; $true; $i++) {
        clear
        Write-Host $title -ForegroundColor White
        Write-Output "[--- Active Directory Config Menu ---]"
        Write-Host "[1] Add New Active Directory User "
        Write-Host "[2] Remove Active Directory User "
        Write-Host "[3] Add New Active Directory Group "
        Write-Host "[4] Remove Active Directory Group "
        Write-Host "[5] Add New Organizational Unit "
        Write-Host "[6] Remove Organizational Unit "
        Write-Host "[7] Add New User in Organization Unit "
        Write-Host "[8] Remove User in Organization Unit "
        Write-Host "[9] Export Active Directory Users "
        Write-Host "[10] Import ACtive Directory Users "
        Write-Host "[11] Exit "        
        $Menu = Read-Host -Prompt "Choose a option"
        
        if ($Menu -eq 1){                 
            for ($i =0;$true;$i++){
                clear
                Write-Host "[--- User Account List ---]"
                Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow
                getInfo(Get-ADUser -Filter *)                
                try {               
                    [String]$User = Read-Host "[+] Insert New Username"
                    if ($User -eq 0){
                        break
                    }                           
                    $Password = Read-Host "[+] Insert Password" -AsSecureString
                    $PlainTextPass = ConvertFrom-SecureString -SecureString $Password -AsPlainText 
                    [boolean]$UserValid = isValid(((Get-ADUser -Filter *).Name),$User,$true)                    
                    if ($UserValid -eq $true){
                        if(New-ADUser -Name $User -AccountPassword $Password -Enabled $true){
                        }else{
                            clear
                            Write-Host "[+] Account Created Succesfully"
                            Write-Host "[--- User Account List ---]"
                            getInfoAfter(Get-ADUser -Filter *)
                            Pause
                            break                      
                        }
                    }else{
                        Write-Warning "[!] Empty Username"
                        Write-Warning "[!] Please Try Again !"
                        Pause
                    }                
                
                }catch [Microsoft.ActiveDirectory.Management.ADPasswordException]{
                    Write-Warning "[!] The password does not meet complexity requirements"
                    Pause
                }catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                    Write-Warning "[!] The username already exist"
                    Pause
                } catch [System.ArgumentException]{
                    Write-Warning "[!] Empty Password"
                    Pause
                } catch{
                    Write-Warning "[!] This Username is used by a Group "
                    Pause
                }
            }
            
        }elseif ($Menu -eq 2){
            for ($i =0;$true;$i++){
                clear
                Write-Host "[--- User Account List ---]"
                Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow
                getInfo(Get-ADUser -Filter *)                
                try {
                    $User = Read-Host "[+] Insert Username"                                                         
                    if ($User -eq 0){
                        break
                    }
                    [boolean]$UserValid = isValid(((Get-ADUser -Filter *).Name),$User,$false)
                    if($UserValid -eq $False){
                        if (Remove-ADUser -Identity $User -Confirm:$False){                    
                        }else{
                            clear
                            Write-Host "[-] Account Removed Succesfully"                            
                            Write-Host "[--- User Account List ---]"
                            getInfo(Get-ADUser -Filter *)
                            Pause
                            break
                        }
                    }else{
                        Write-Warning "[!] The Username doesn't Exist"
                        Write-Warning "[!] Please Try Again! "
                        Pause
                    }                                                                             
                }catch{
                    Write-Warning "[!] The Username doesnt exist"
                    Pause
                }          
            }
        }elseif ($Menu -eq 3){
            for ($i =0;$true;$i++){
                clear
                Write-Host "[--- Group List ---]"
                Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow
                getInfo(Get-ADGroup -Filter *)
                try{
                    [String]$Name = Read-Host "[+] New Group "                    
                    if($Name -eq 0){
                        break
                    }elseif(New-ADGroup -Name $Name -GroupScope DomainLocal){
                    }else{
                        clear
                        Write-Host "[+] Local Doamin Group Added Sussecfully"
                        getInfo(Get-ADGroup -Filter *)
                        Pause
                        break
                    }
                                    
                }catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                    Write-Warning "[!] User Account Have The Same Name "
                    Pause 
                }catch{
                    Write-Warning "[!] Local Group Alredy Exist "
                    Pause                 
                }

            }
        }elseif ($Menu -eq 4){
            for ($i =0;$true;$i++){
                clear
                Write-Host "[--- Group List ---]"
                Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow
                getInfo(Get-ADGroup -Filter *)
                try{
                    [String]$Name = Read-Host "[+] Remove Group Name"
                    if($Name -eq 0){
                        break
                    }elseif(Remove-ADGroup -Identity $Name -Confirm:$false){
                    }else{
                        clear
                        Write-Host "[-] Local Domain Group Removed Succesfully"
                        getInfo(Get-ADGroup -Filter *)
                        Pause
                    }
                    Remove-ADGroup -Identity $Name -Confirm:$false
                }catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                    Write-Warning "[!] Group Name Doest Exist"
                    Pause 
                }catch{
                    Write-Warning "[!] Local Group Alredy Exist "
                    Pause                 
                }

            }                        
        }elseif ($Menu -eq 5){
            for ($i = 0; $true; $i++) {
                clear
                Write-Host "[--- List Organization Units --- "
                Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow
                getInfo(Get-ADOrganizationalUnit -Filter *)
                try{
                    $ou = Read-Host -Prompt "[+] Insert Organization Unit Name"
                    if ($ou -eq 0){
                        break
                    }elseif (New-ADOrganizationalUnit -Name $ou){
                    
                    }else{
                        clear
                        Write-Host "[+] Organization Unit Added Succesfully"
                        getInfoAfter(Get-ADOrganizationalUnit -Filter *)
                        Start-Sleep 2
                    }
                }catch [Microsoft.ActiveDirectory.Management.ADException]{
                    Write-Warning "[!] Organization Unit Name Already Exist "
                    Pause
                }              
            }        
        }elseif ($Menu -eq 6){
            for ($i = 0; $true; $i++) {
                clear
                Write-Host "[--- List Organization Units --- "
                Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow
                getInfo(Get-ADOrganizationalUnit -Filter *)
                try{
                    [String] $ou = Read-Host "[+] Remove Organization Unit Name"
                    if ($ou -eq 0){
                        break
                    }elseif (Get-ADOrganizationalUnit -Filter 'Name -like $ou' | Set-ADObject -ProtectedFromAccidentalDeletion:$false -PassThru | Remove-ADOrganizationalUnit -Confirm:$false){
                        Write-Host Hi
                    }else{
                        clear
                        Write-Host "[+] Organization Unit Removed Succesfully"
                        getInfo(Get-ADOrganizationalUnit -Filter *)
                        Pause                        
                        
                    }
                }catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                    Write-Warning "[!] Organization Unit Name Already Exist "
                    Pause
                }              
            }            
        }elseif($Menu -eq 7){
            for($i=0;$true;$i++){
                clear
                Write-Host "[--- List Users and Organizations Units --- ]"
                Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow
                $UserOu = (Get-ADUser -Filter *)
                $UserOu += (Get-ADOrganizationalUnit -Filter *)
                Write-Output $UserOu | Format-Table -Property Name, DistinguishedName
                $User = Read-Host "[+] User Account ]"
                if($User -eq 0){
                    break
                }
                $Uo = Read-Host "[+] Organization Unit ]"                
                try{                
                    [boolean]$isValid = isValid((Get-ADUser -Filter * -SearchBase (Get-ADOrganizationalUnit -Filter 'Name -like $Uo')),$User,$true)
                    Pause                
                    if($isValid -eq $true){
                        if (Move-ADObject -Identity ((Get-ADUser -Filter 'Name -like $User ').DistinguishedName) -TargetPath ((Get-ADOrganizationalUnit -Filter 'Name -like $Uo').DistinguishedName)){
                    
                        }else{
                            clear
                            Write-Host "[+] User Moved Succesfully"
                            (Get-ADUser -Filter * -SearchBase  ((Get-ADOrganizationalUnit -Filter 'Name -like $Uo').DistinguishedName)).Name
                            Pause
                        }
                    }else{
                        Write-Warning "[!] User Is Already In The Organization Unit"
                        Write-Warning "[!] Please Try Again!"
                        Pause
                    }
                    
                }catch [System.Management.Automation.ParameterBindingValidationException],[Microsoft.ActiveDirectory.Management.ADException]{
                    Write-Warning "[!] Empty User or Organization Unit "
                    Write-Warning "[!] Please Try Again "
                    Pause
                }catch{
                    Write-Warning "[!] Wrong User or Organization Unit "
                    Write-Warning "[!] Please Try Again "
                    Pause
                }
                
            }            
        }elseif($Menu -eq 8){ # Is not finished
            for ($i=0;$true;$i++){
                try{    
                    clear
                    Write-Host "[--- Organizations Units List --- ]"
                    Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow
                    (Get-ADOrganizationalUnit -Filter *).Name
                    $Ou = Read-Host "[+] Organization Name To List"                
                    (Get-ADUser -Filter * -SearchBase (Get-ADOrganizationalUnit -Filter 'Name -like $Ou')).Name
                    $User = Read-Host "[-] User To Move Out"
                    if ($Ou -eq 0 -or $User -eq 0){
                        break
                    }
                    [boolean]$isValid = isValid((Get-ADUser -Filter * -SearchBase (Get-ADOrganizationalUnit -Filter 'Name -like $Uo')),$User,$true)
                    for($i=0;$true;$i++){
                        if($isValid -eq $true){
                            if(Get-ADUser -Filter 'Name -like $User' | Move-ADObject -TargetPath "CN=Users,DC=fsociety,DC=local"){                            
                            }else{
                                Write-Host "[+] The User Moved Succesfully "
                                Pause
                                break
                            }
                            
                        }                        
                    }
                    if($isValid -eq $true){
                        Get-ADUser -Filter 'Name -like $User' | Move-ADObject -TargetPath "CN=Users,DC=fsociety,DC=local"
                        Pause
                    }                                
                }catch [Microsoft.ActiveDirectory.Management.ADException]{
                    Write-Warning "[!] The Organization Unit Or User Do Not Exist "
                    Write-Warning "[!] Please Try Again "
                    Pause
                }catch {
                    Write-Warning "[!] The Organization Unit Do Not Exist "
                    Write-Warning "[!] Please Try Again "
                    Pause
                }
            }
        }elseif($Menu -eq 9){
            clear                
            Write-Host "[--- List Of Active Directory Objects ---]"
            foreach ($Object in (Get-ADObject -Filter *)){
                Write-Host $Object
            }
            Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow                
            for($i=0;$true;$i++){
                    
                    $AdObject = Read-Host "[+] Select The Object You Want To Export"
                    $isValid = isValid((Get-ADObject -Filter *),$AdObject,$false)
                    if($isValid -eq $true){
                        $AdObject = (Get-ADObject -Filter 'Name -like $AdObject').DistinguishedName
                        $Path = Read-Host "[+] Path To Save Csv [Default Current Directory]"
                        if($Path -contains ".csv"){
                            Get-ADUser -Filter * -SearchBase $AdObject -Properties Name | Export-Csv -Path $Path
                            Write-Host "[+] Export Successfully "
                            cat $Path
                            Pause
                        }else{
                            $Path += ".csv"
                            Get-ADUser -Filter * -SearchBase $AdObject -Properties Name | Export-Csv -Path $Path
                            Write-Host "[+] Export Succesfully "
                            cat $Path
                            Pause
                        }
                        
                    }else{
                        Write-Warning "[!] The Object Do Not Exist "
                        Write-Warning "[!] Please Try Again "
                        Pause
                    }
            }
        

        }elseif($Menu -eq 10){
            for($i=0;$true;$i++){
                clear
                Write-Host "[--- Import Users From Csv ---]"
                Write-Host "[0] Back To Menu " -ForegroundColor DarkYellow
                try{
                    $Domain = (Get-ADForest).Name
                    (Get-ADOrganizationalUnit -Filter *).Name
                    $Ou = Read-Host "[+] Organization Unit To Put Users "
                    $UserOu += (Get-ADOrganizationalUnit -Filter 'Name -like $Ou').DistinguishedName
                    Write-Debug $Ou
                    if($Ou -eq 0 -Or $CsvFile -eq 0){
                        break
                    }
                    $CsvFile = Import-Csv (Read-Host "[+] Csv File ") -Delimiter ","
                    if($CsvFile){                                       
                        foreach($User in $CsvFile){
                            $FullName=$User.FullName
                            $givenName=$User.givenName
                            $Company=$User.company
                            $Department=$User.department
                            $title=$User.title
                            $telephoneNumber=$User.telephoneNumber
                            $City=$User.City
                            $sAMAccountName=$User.sAMAccountName
                            $userPrincipalName=$User.sAMAccountName+$Domain
                            $userPassword=$User.Password
                            $expire=$null

                            New-ADUser -PassThru -Path $UserOu -Enabled $True -ChangePasswordAtLogon $True -AccountPassword (ConvertTo-SecureString $userPassword -AsPlainText -Force) -CannotChangePassword $False -City $City -Company $Company -Department $Department -Title $title -OfficePhone $telephoneNumber -DisplayName $FullName -GivenName $givenName -Name $FullName -SamAccountName $sAMAccountName -UserPrincipalName $userPrincipalName                                                       
                        }
                    clear
                    Write-Host "[+] Users Added Succesfully"
                    (Get-ADUser -Filter * -SearchBase (Get-ADOrganizationalUnit -Filter 'Name -like $Ou')).Name
                    Pause
                    break
                    }
                }catch [Microsoft.ActiveDirectory.Management.ADException]{
                    Write-Warning "[!] Wrong Organization Unit "
                    Write-Warning "[!] Please Please Try Again "
                    Pause
                }catch{
                    Write-Warning "[!] Wrong Csv File / Empty Column In Csv File"
                    Write-Warning "[!] Please Try Again "
                    Pause
                }
            }

        }elseif($Menu -eq 11){
            clear
            Write-Host $Author
            pause
            break            
        }
    }

}else{
    Write-Warning "[--- You Don't Have Domain Server ---]"
}
