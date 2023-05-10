    <#
        .SYNOPSIS
            Updates the NTFS permissions on existing folders for FSLogix Profile Containers.
        .DESCRIPTION
            This cmdlet is used to fix or update the NTFS permissions for the folders FSLogix uses to storage profile containers.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,Position=0)]
        [System.String]$Path,

        [Parameter(Mandatory=$false,Position=1)]
        [Switch]$FlipFlopDirectoryName,

        [Parameter(Mandatory=$false,Position=2)]
        [Switch]$Recurse
    )

    BEGIN {
        Function _GetADAttributes {
            [CmdletBinding()]
            Param (
                   [String]$Property,
                   [String]$Value,
                   [Switch]$AllProperties,
                   [Switch]$Search
            )
        
            $ADSearch = New-Object System.DirectoryServices.DirectorySearcher
            $ADSearch.SearchRoot = "GC://dc=contoso,dc=com"
        
            If ($AllProperties) {
                   #Write-Debug "Check AllProperties Switch"
                   $ADSearch.Filter = "(&($Property=$Value))"
                   $ADInfo = $ADSearch.FindOne() | Select-Object -ExpandProperty Properties
                   Return $ADInfo
            }
            Else {
                   $colPropList = @(
                          "givenname", "sn", "samaccountname", "mail", "department", "distinguishedname", "canonicalname", "userprincipalname", "mailnickname", "pwdlastset", "lastlogontimestamp", "proxyaddresses", "whencreated", "whenchanged"
                   )
           
                   $ADSearch.PropertiesToLoad.AddRange($colPropList)
        
                   If ($Search) {
                          #Write-Debug "Test Search"
                          $ADSearch.Filter = "(&($Property=*$Value*))"
                          $ADResult = $ADSearch.FindAll()
                          If ($ADResult.Count -eq 1) {
                                 $ADInfo = $ADResult | Select-Object `
                                 @{N = "samaccountname"; E = { $_.Properties["samaccountname"] } },
                                 @{N = "mail"; E = { $_.Properties["mail"] } },
                                 @{N = "distinguishedname"; E = { $_.Properties["distinguishedname"] } },
                                 @{N = "userprincipalname"; E = { $_.Properties["userprincipalname"] } },
                                 @{N = "mailnickname"; E = { $_.Properties["mailnickname"] } },
                                 @{N = "proxyaddresses"; E = { $_.Properties["proxyaddresses"] } },
                                 @{N = "whencreated"; E = { $_.Properties["whencreated"] } },
                                 @{N = "whenchanged"; E = { $_.Properties["whenchanged"] } },
                                 @{N = "canonicalname"; E = { $_.Properties["canonicalname"] } },
                                 @{N = "givenname"; E = { $_.Properties["givenname"] } },
                                 @{N = "sn"; E = { $_.Properties["sn"] } },
                                 @{N = "pwdlastset"; E = { $_.Properties["pwdlastset"] } },
                                 @{N = "lastlogontimestamp"; E = { $_.Properties["lastlogontimestamp"] } }
        
                                 Return $ADInfo
                          }
                          ElseIf ($ADResult.Count -gt 1) {
                                 Return $ADResult
                          }
                          Else {
                                 Write-Warning "No Results Found!"
                          }
                   }
                   Else {
                          #Write-Debug "No Search"
                          $ADSearch.Filter = "(&($Property=$Value))"
                          $ADResult = $ADSearch.FindOne()
                          $ADInfo = $ADResult | Select-Object `
                          @{N = "samaccountname"; E = { $_.Properties["samaccountname"] } },
                          @{N = "mail"; E = { $_.Properties["mail"] } },
                          @{N = "distinguishedname"; E = { $_.Properties["distinguishedname"] } },
                          @{N = "userprincipalname"; E = { $_.Properties["userprincipalname"] } },
                          @{N = "mailnickname"; E = { $_.Properties["mailnickname"] } },
                          @{N = "proxyaddresses"; E = { $_.Properties["proxyaddresses"] } },
                          @{N = "whencreated"; E = { $_.Properties["whencreated"] } },
                          @{N = "whenchanged"; E = { $_.Properties["whenchanged"] } },
                          @{N = "canonicalname"; E = { $_.Properties["canonicalname"] } },
                          @{N = "givenname"; E = { $_.Properties["givenname"] } },
                          @{N = "sn"; E = { $_.Properties["sn"] } },
                          @{N = "pwdlastset"; E = { $_.Properties["pwdlastset"] } },
                          @{N = "lastlogontimestamp"; E = { $_.Properties["lastlogontimestamp"] } }
        
                          Return $ADInfo
                   }
            }
        }

        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        # Check to see if the Path parameter was provided
        Write-Verbose ("Checking the provided path: '{0}'" -f $Path)
        # Test the path
        If (Test-Path -Path $Path) {
            Write-Verbose ("Collecting FSLogix Profile Directories")
            # Collect folders matching '_S-1'
            If ($FlipFlopDirectoryName) { $profileFolders = Get-ChildItem -Path $Path -Directory -Recurse:$Recurse | Where-Object { $_.Name.Contains("_S-1") } }
            Else { $profileFolders = Get-ChildItem -Path $Path -Directory -Recurse:$Recurse | Where-Object { $_.Name.StartsWith("S-1") } }
            Write-Verbose ("Found {0} Folders to Process from: {1}" -f $profileFolders.Count, $Path)
        }
        Else {
            Write-Warning ("Verify that the '{0}' path is valid" -f $Path)
            Break
        }
    }
    PROCESS {
        $i = 1
        foreach ($Item in $profileFolders) {
            Write-Progress -Activity "Processing Folders" -Status ("Working on {0} of {1}" -f $i, $profileFolders.Count) -CurrentOperation $Item.FullName -PercentComplete (($i / $profileFolders.Count) * 100)
            # Parse folder name for username
            If ($FlipFlopDirectoryName) {
                [System.Security.Principal.SecurityIdentifier]$sid = $item.Name.Split("_")[1]
                $userName = $item.Name.Split("_")[0]
            }
            Else {
                [System.Security.Principal.SecurityIdentifier]$sid = $item.Name.Split("_")[0]
                $userName = $item.Name.Split("_")[1]
            }

            $userAccount = $null
            # query AD to check if user exsists
            $userAccount = _GetADAttributes -Property "samAccountName" -Value $userName

            # if the user prinicpal is active 
            If ($null -ne $userAccount) {

                $NTAccount = $sid.Translate([System.Security.Principal.NTAccount]).Value
                # ACL Permission Hashtable
                $accessHashTable = @{
                    $NTAccount                  = "Modify"
                    "SYSTEM"                    = "FullControl"
                    "CONTOSO\Administrators"    = "FullControl"
                }

                # Get ACL(s) on folder
                $aclObject = Get-Acl -Path $Item.FullName -ErrorAction SilentlyContinue

                # Check for ACL Object
                If ($aclObject) {
                    # Clear existing permissions and block inheritance
                    $aclObject.SetAccessRuleProtection($true, $false)

                    # Set new ACL(s) on ACLObject looping through the access hash table
                    foreach ($Account in $accessHashTable.Keys) {
                        # Create the permission object per account in the hash table
                        $permissionObject = $Account, $accessHashTable[$Account], "ContainerInherit,ObjectInherit", "None", "Allow"
                        # Create ACL access rule and apply permission object
                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($permissionObject)
                        # Apply the access rule to the ACL Object
                        $aclObject.SetAccessRule($accessRule)
                    } # end foreach loop

                    # Apply updated ACL object to ACL Path
                    $initalAclCheck = Compare-Object -ReferenceObject $aclObject.Access -DifferenceObject (Get-Acl -Path $Item.FullName -ErrorAction SilentlyContinue).Access
                    If ($initalAclCheck) {
                        Set-Acl -Path $Item.FullName -AclObject $aclObject -ErrorAction SilentlyContinue
                        
                        # Get newly applied ACL(s)
                        $newAclObject = Get-Acl -Path $Item.FullName -ErrorAction SilentlyContinue
                        
                        If ($newAclObject) {
                            # Compare modifed ACL to fetched ACL Object
                            $aclValidation = Compare-Object -ReferenceObject $aclObject.Access -DifferenceObject $newAclObject.Access

                            If ($aclValidation) { Write-Warning ("ACL(s) on the folder '{0}', were not applied correctly" -f $Item.FullName) }
                            Else { Write-Host ("[SUCCESS] Applied new ACL(s) on folder '{0}'" -f $Item.FullName) -ForegroundColor Green }
                        }
                        Else { Write-Warning ("Unable to get newly applied ACL(s) from folder '{0}'" -f $Item.FullName) }
                    }
                    Else { Write-Host ("[INFO] No change need for ACL(s) on folder '{0}'" -f $Item.FullName) -ForegroundColor Cyan }
                }
                Else { Write-Warning ("Unable to get ACL(s) from folder '{0}'" -f $Item.FullName) }
            }
            Else { Write-Warning ("Unable to location User Account from Active Directory Global Catalog using '{0}'" -f $userName) }
            $i++
        } # end foreach loop
        Write-Progress -Activity "Processing Folders" -Completed
    }
    END {
        $stopWatch.Stop()
        Write-Verbose ("Process Completed in: {0}" -f $stopWatch.Elapsed)
    }
