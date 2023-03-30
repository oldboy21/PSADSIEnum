<#
    Enum-DomainsAndGroups.ps1

    Retrieve nested domain trusts and nested group memberships of a user

    AUTHOR: Vincenzo Santucci
    CO-AUTHOR: Sander Maas

    USAGE:

    Load the module using:
    Import-Module .\Enum-DomainsAndGroups.ps1

    Functions:

    Get-NestedDomainTrusts

    Get-NestedGroupMemberships [-username] [-logondomain]
    (alias) Enum-DomainsAndGroups [-username] [-logondomain]
#>


<#
    .FUNCTION

        Get-NestedDomainTrusts

    .SYNOPSIS
        
        This function can be used to fetch nested domain trusts.

    .DESCRIPTION
    
        Obtain a list of nested domain trusts.

    .EXAMPLE

        Get-NestedDomainTrusts
#>

function Get-NestedDomainTrusts {
    Write-Host "Finding all nested domain trusts of your current domain that your current user is logged on to."

    $global:final = @() 
    $global:array = @()
    $global:AllDomains = @()
    $global:BlacklistDomains = @()
    $global:AllDomains += $env:USERDNSDOMAIN

    Get-DomainTrusts $env:USERDNSDOMAIN

    Write-Host "-----------------------------------------"
    Write-Host "Found the following nested domain trusts:"
    Write-Host "-----------------------------------------"
    $global:AllDomains
    Write-Host "-----------------------------------------"
}


<#
    .FUNCTION

        Get-NestedGroupMemberships / Enum-DomainsAndGroups (alias)

    .SYNOPSIS
        
        This function can be used to fetch nested domain trusts and nested group memberships of a user.

    .DESCRIPTION
    
        Obtain a list of nested group memberships and/or domain trusts.

    .PARAMETER username (optional)

        Specify a username for which the nested group memberships should be retrieved. 
        Default: your current user

    .PARAMETER logondomain (optional)

        Specify the logondomain of the user for which the nested group memberships should be retrieved. 
        Default: your current logondomain

    .EXAMPLE

        Get-NestedGroupMemberships
        Get-NestedGroupMemberships -username bob -logondomain contoso.local
        Enum-DomainsAndGroups -username bob -logondomain contoso.local 
#>

function Get-NestedGroupMemberships {
    param(
        [ValidateNotNullOrEmpty()]
        [String]
        $username = $env:USERNAME,
        [ValidateNotNullOrEmpty()]
        [String]
        $logondomain = $env:USERDNSDOMAIN
    )

    Write-Host "Finding all nested domain trusts of the current domain that your are logged on to."

    $global:final = @() 
    $global:array = @()
    $global:AllDomains = @()
    $global:BlacklistDomains = @()
    $global:AllDomains += $env:USERDNSDOMAIN

    Get-DomainTrusts $env:USERDNSDOMAIN

    Write-Host "-----------------------------------------"
    Write-Host "Found the following nested domain trusts:"
    Write-Host "-----------------------------------------"
    $global:AllDomains
    Write-Host "-----------------------------------------"
    
    Write-Host "Finding all NestedGroupMemberships across trusted domains for user: $username with logondomain: $logondomain."

    Check-NestedGroupMemberships $global:AllDomains -username $username -logondomain $logondomain
    $global:final = $global:final + $global:array
    Write-Host "-------------------------------------------------------------------------"
    Write-Host "Found the following nested group memberships of all nested domain trusts:"
    Write-Host "-------------------------------------------------------------------------"
    $global:final
    Write-Host "-------------------------------------------------------------------------"
}
 


function Get-Group-SID {
Param (
    $GroupName, $DomainG
  )
  
try {
$objUser = New-Object System.Security.Principal.NTAccount($DomainG ,$GroupName)
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
}catch {
  Write-Verbose "Could not lookup SID for group: $GroupName"
  return ""
}
return $strSID

}

function Get-SID{
    Param (
    $DSIdentity,
    $DSDomain
  )
  
  return (New-Object System.Security.Principal.NTAccount($DSIdentity + "@" + $DSDomain)).Translate([System.Security.Principal.SecurityIdentifier]).value
}


function Get-DomainTrusts {
  Param($domain)
  try {
    $Search = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
    $Search.Filter = "(objectClass=trustedDomain)"
    Write-Verbose "Searching trusts for domain: $($domain)"

    foreach ($domainEntry in $($Search.FindAll()))
    {
      Write-Verbose "Going through entry $($domainEntry.properties.cn)"
      if (!($global:AllDomains -contains $domainEntry.properties.cn)) {
        $global:AllDomains += $domainEntry.properties.cn
        Get-DomainTrusts $domainEntry.properties.cn
      }
    }
  } catch {
    Write-Host "Error while trying to retrieving trusted domains for:" $domain -ForegroundColor Red
    Write-Debug $_
    $global:BlacklistDomains += $domainEntry.properties.cn
  }
}


function get-groups-of-user {
    Param($SID,$domains)
   
   $membership = @()
   $crossDomainMembership = @{}

   foreach ($domain in $domains) {
     try {
         if (!($global:BlacklistDomains -contains $domain)) {
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
            $Searcher.Filter = "objectSID=$($SID)"
            $Searcher.FindAll()

            $groups = $Searcher.FindAll().Properties.memberof -replace '^CN=([^,]+).+$','$1' | out-string

            $membership = $groups.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
    
            if ($env:USERDNSDOMAIN -eq $domain) {
              $membership += "Domain Users"
              $membership += "Authenticated Users"
            }
    
            $crossDomainMembership.Add($domain, $membership)
        }
    }
    catch {
        Write-Host "Error while trying to retrieve groups for domain:"$domain -ForegroundColor Red
    }
  }
  

  return $crossDomainMembership
}



function printhasht{
Param($AAA)
    foreach ($chiave in $AAA.keys){
            foreach ($membro in $AAA.$chiave){
                write-host $membro
            }
     }
}



function get-nested {
    Param ($SID, $Domain, $DomainToLookUp)
    try {
        if (!($global:BlacklistDomains -contains $Domain)) {
          $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$($Domain)")
          $Searcher.Filter = "objectSID=$($SID)"
          $groups = $Searcher.FindAll().Properties.memberof -replace '^CN=([^,]+).+$','$1' | out-string    
          $membership = $groups.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
          if ($membership.Count -gt 0){
      
              foreach ($member in $membership) {
                  #write-host "Found: " $member " looking into " $Domain
                  $global:array += ($member + "\" + $Domain)
                  $SID = Get-Group-SID $member $Domain 
                  if ($SID) {
                          #$global:array += ($member + "\" + $Domain)
                          foreach ($domaintlu in $DomainToLookUp){
                            get-nested $SID $domaintlu $DomainToLookUp
                          }
                  }
              }
          }
        }
    }
    catch {
      write-host "Error while trying to retrieve the nested group memberships for: " $Domain -ForegroundColor Red
    }
}


function Check-NestedGroupMemberships {

  param(
      [ValidateNotNullOrEmpty()]
      [String[]]
      $CrossDomainGroupMemberships,

      [ValidateNotNullOrEmpty()]
      [String]
      $username,

      [ValidateNotNullOrEmpty()]
      [String]
      $logondomain
  )

  $DirectgroupMembership = @{}
  
  $SIDUser = Get-SID $username $logondomain #i get the SID from username
  
  $DirectgroupMembership = get-groups-of-user $SIDUser $CrossDomainGroupMemberships
  
  foreach ($domain in @($DirectgroupMembership.keys)){
  write-host "Search for group memberships in domain: "$domain 
      foreach ($group in @($DirectgroupMembership.$domain)) {
              if ($group -ne $null) {
                  $global:final += ($group + "\" + $domain)
                  foreach ($domaintlu in $CrossDomainGroupMemberships){
                    $testSID = Get-Group-SID $group $domain
                      if ($testSID){
                          get-nested $testSID $domaintlu
                      }
                  }
              }
      }
  }
}

Set-Alias Enum-DomainsAndGroups Get-NestedGroupMemberships
