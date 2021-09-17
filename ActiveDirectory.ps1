#Pt.4 Automatisation OU Active Directory
# Author Jordi Forés Garcia

#First we test if the user have the Domain installed.
if(((Get-ADForest).Name).Equals((Get-ADForest).Name)){

    Write-Output "Checking Domain Forest Name"
    $ForestName = (Get-ADForest).Name
    Write-Output $ForestName
    Write-Output "Finding the Menu"
    Start-Sleep 5
    for ($i = 0; $true; $i++) {
        Write-Output "--Active Directory Config Menu--"
        Write-Output "Add New Organizational Unit (1)"
        Write-Output "Add New User in Organization Unit (2)"
        Write-Output "Add New Goup in Organization Unit (3)"
        Write-Output "Add User to a Local Goup (4)"
        Write-Output "-- Information --"
        Write-Output "Domain Info (5)"
        Write-Output "Forest Info (6)"
        Write-Output "Show All Organizational Units (7)"
        Write-Output "Show All User Organizational Units (8)"
        Write-Output "Show All Goups Organizational Units (9)"
        Write-Output "End (10)"
        $Menu = Read-Host -Prompt "Choose a option"
        
        if ($Menu -eq 1 ) {            
            for ($i = 0; $true; $i++) {                
                $ou = Read-Host -Prompt "Insert OU Name"
                if((Get-ADOrganizationalUnit -Filter 'Name -like "*"').Name -contains $ou){
                    Write-Output "The Name is already used, Try Again"    
                }else{
                    New-ADOrganizationalUnit $ou -path (Get-ADDomain).DistinguishedName
                    Write-Output "Organization Unit Created Successful"
                    for ($i = 0; $true; $i++) {
                        $Answer = Read-Host -Prompt "Do you want to list the OU ? (Y)es or (N)o"
                        if($Answer -eq "Y"){                            
                            Write-Output "List if Organizational Units"
                            (Get-ADOrganizationalUnit -Filter *).Name  
                            Read-Host "Press ENTER to continue..."
                            break
                        }
                    }
                    break
                }                
            }
        }elseif ($Menu -eq 2) {
            for ($i = 0; $true; $i++) {
                
            }
        }elseif($Menu -eq 3){

        }elseif($Menu -eq 4){

        }elseif($Menu -eq 5){
            Write-Output "----------------------Get-ADDomain-------------------------"
            Get-ADDomain
            Read-Host "Press ENTER to continue..."
        }elseif($Menu -eq 6){
            Write-Output "----------------------Get-ADForest-------------------------"
            Get-ADForest
            Read-Host "Press ENTER to continue..."
        }elseif($Menu -eq 7){
            for ($i = 0; $true; $i++) {                
                Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name,DistinguishedName -A
                Read-Host "Press ENTER to continue..."
                $uo = (Get-ADDomain).DistinguishedName                
                for ($i = 0;$true; $i++) {
                    $NameOU = Read-Host -prompt "OU Name "
                    if((Get-ADOrganizationalUnit -Filter 'Name -like "*"').Name -contains $NameOU){
                        Get-ADGroup -Filter * -SearchBase "OU=$NameOU,$uo"| Format-Table Name,DistinguishedName,GroupScope
                        $Bye = Read-Host -prompt "Want to consultate another OU ? (Y)es or (N)o "   
                        if($Bye -eq "N"){
                            break
                        }
                    }else{
                        Write-Output "¡This Organization Unit doesn't exist!"
                    }
                }
                break                
            }
        }elseif($Menu -eq 8){
            Get-ADUser -Filter 'Name -like "*"' | Format-Table Name,DistinguishedName,Enabled
            $Filter = Read-Host "Want to filter by a User Name? (Y)es or (N)o"
            for ($i = 0; $Filter -eq "Y"; $i++) {                
                    for ($i = 0;$true; $i++) {
                        [String]$UserName = Read-Host "User Name "                 
                        if((Get-ADUser -Filter 'Name -like "*"').Name -contains $UserName){
                            Get-ADUser -Filter 'Name -like $UserName'
                            $Bye = Read-Host "Want to consultate another User ? (Y)es or (N)o "   
                            if($Bye -eq "N"){
                                break
                            }
                        }else{
                            Write-Output "¡This User Name doesn't exist!"
                        }
                    }
            }
            Write-Output "¡The main menu will apears!"
            Start-Sleep 5
        }elseif($Menu -eq 9){
            $uo = (Get-ADDomain).DistinguishedName
            Get-ADGroup -Filter * -SearchBase "$uo"| Format-Table Name,DistinguishedName,GroupScope
            Read-Host "Press ENTER to continue..."
        }elseif($Menu -eq 10){
            Write-Output "¡Thx for using my script!"
            Write-Output "Author -> Jordi Fores Garcia"
            break            
        }
    }

}else{
    Write-Output "¡You don't have a Domain Server!"
}