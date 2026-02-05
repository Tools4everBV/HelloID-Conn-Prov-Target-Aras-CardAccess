####################################################################
# HelloID-Conn-Prov-Target-Aras-CardAccess-ImportPermissions-Group
# PowerShell V2
####################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Resolve-Aras-CardAccessError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = (($httpErrorObj.ErrorDetails) | ConvertFrom-Json)
            if ($errorDetailsObject.exceptionMessage) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.exceptionMessage
            } elseif ($errorDetailsObject.error) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error
            } else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        } catch {
            $httpErrorObj.FriendlyMessage = "[$($httpErrorObj.ErrorDetails)]"
            Write-Warning $_.Exception.Message
        }
        Write-Output $httpErrorObj
    }
}
#endregion

try {
    Write-Information 'Starting Aras-CardAccess permission group entitlement import'

    # get auth token and set header
    $splatTokenParams = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/token"
        Method  = 'POST'
        Headers = @{
            'content-type' = 'application/x-www-form-urlencoded'
            'accept'       = 'application/json'
        }
        Body    = @{
            username   = $actionContext.Configuration.UserName
            password   = $actionContext.Configuration.Password
            grant_type = 'password'
        }
    }
    $accessToken = (Invoke-RestMethod @splatTokenParams).access_token

    $headers = @{
        Authorization  = "Bearer $($accessToken)"
        'content-type' = 'application/json'
        Accept         = 'application/json'
    }

    $splatGetBadges = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/Badges/AllBadgeHolders?partitionId=$($actionContext.Configuration.PartitionId)"
        Method  = 'Get'
        Headers = $headers
    }
    $importedAccounts = Invoke-RestMethod @splatGetBadges


    $splatImportPermissionParams = @{
        Uri    = "$($actionContext.Configuration.BaseUrl)/Access/AccessGroups"
        Method = 'GET'
        Header = $headers
    }
    $importedPermissions = Invoke-RestMethod @splatImportPermissionParams

    foreach ($importedPermission in ($importedPermissions | Where-Object { $_.ValueMember -ne $actionContext.References.Permission.Reference })) {
        # Get all account references where one of the AG# properties contains permission reference.
        $badgeReferences = [System.Collections.Generic.List[int]]::new()
        foreach ($account in $importedAccounts) {
            $agValues = $account.PSObject.Properties.Where({ $_.Name -match '^AG\d+$' -and $_.Value -ne $actionContext.Configuration.NoAccessPermissionId }).Value
            if ($agValues -contains $importedPermission.ValueMember) {
                $badgeReferences.Add($account.Badge)
            }
        }

        $permission = @{
            PermissionReference = @{
                Reference = $importedPermission.ValueMember
            }
            Description         = "$($importedPermission.DisplayMember)"
            DisplayName         = "$($importedPermission.DisplayMember)"
            AccountReferences   = $null
        }

        # The code below splits a list of permission members into batches of 100
        # Each batch is assigned to $permission.AccountReferences and the permission object will be returned to HelloID for each batch
        # Ensure batching is based on the number of account references to prevent exceeding the maximum limit of 500 account references per batch
        $batchSize = 500
        for ($i = 0; $i -lt $badgeReferences.Count; $i += $batchSize) {
            $permission.AccountReferences = $badgeReferences[$i..([Math]::Min($i + $batchSize - 1, $badgeReferences.Count - 1))]
            Write-Output $permission
        }
    }
    Write-Information 'Aras-CardAccess permission group entitlement import completed'
} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Aras-CardAccessError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import Aras-CardAccess permission group entitlements. Error: $($errorObj.FriendlyMessage)"
    } else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import Aras-CardAccess permission group entitlements. Error: $($ex.Exception.Message)"
    }
}