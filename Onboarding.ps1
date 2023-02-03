Import-Module ActiveDirectory

try {
    $OU = Read-Host -Prompt "Enter the distinguished name of the target OU (e.g. 'OU=YourOrgUnit,DC=YourDomainController,DC=local')"
    if([string]::IsNullOrWhiteSpace($OU)) {
        $OU = "OU=DefaultOrgUnit,DC=YourDomainController,DC=local"
    } else {
        $OU = "OU=$OU,OU=DefaultOrgUnit,DC=YourDomainController,DC=local"
    }

    $Username = Read-Host -Prompt "Enter the username for the new user"
    if([string]::IsNullOrWhiteSpace($Username)) {
        throw "Error: Please enter a valid username."
    }

    $Password = Read-Host -Prompt "Enter the password for the new user" -AsSecureString
    if([string]::IsNullOrWhiteSpace($Password)) {
        throw "Error: Please enter a valid password."
    }

    $FirstName = Read-Host -Prompt "Enter the first name for the new user"
    if([string]::IsNullOrWhiteSpace($FirstName)) {
        throw "Error: Please enter a valid first name."
    }

    $LastName = Read-Host -Prompt "Enter the last name for the new user"
    if([string]::IsNullOrWhiteSpace($LastName)) {
        throw "Error: Please enter a valid last name."
    }

    $UserPrincipalName = "$Username@YourDomainController.local"
    $Name = "$FirstName $LastName"

    try {
        New-ADUser -Name $Name -GivenName $FirstName -Surname $LastName -SamAccountName $Username -UserPrincipalName $UserPrincipalName -Path $OU -AccountPassword $Password -Enabled $True
        Write-Host "User '$Username' has been created in the target OU '$OU'"
    } catch {
        throw "Error: Failed to create user. $_"
    }

} catch {
    Write-Host $_.Exception.Message
}
