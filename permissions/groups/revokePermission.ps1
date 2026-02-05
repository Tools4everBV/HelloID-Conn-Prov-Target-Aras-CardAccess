#################################################################
# HelloID-Conn-Prov-Target-Aras-CardAccess-RevokePermission-Group
# PowerShell V2
#################################################################

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

# Begin
try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

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

    Write-Information 'Verifying if a Aras-CardAccess account exists'
    $splatGetBadge = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/Badges/BadgeInfo?Badge=$($actionContext.References.Account)&Facility=$($actionContext.Configuration.Facility)"
        Method  = 'Get'
        Headers = $headers
    }
    $correlatedAccount = (Invoke-RestMethod @splatGetBadge) | Select-Object -First 1

    if ($null -ne $correlatedAccount) {
        $action = 'RevokePermission'
    } else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'RevokePermission' {
            # Build AGNos array, Get the value from all properties from correlatedAccount starting with AG and a number after.
            $agnos = [System.Collections.ArrayList]@(
                $correlatedAccount.PSObject.Properties | Where-Object { $_.Name.StartsWith('AG') -and $_.Value -ne $actionContext.Configuration.NoAccessPermissionId } | ForEach-Object { [int]$_.Value }
            )
            # Remove the permission from the AGNos array to update the account without the permission.
            $agnos = $agnos | Where-Object { $_ -ne $actionContext.References.Permission.Reference }

            # If the last permission gets revoked grant the 'no access'
            if ($agnos.count -eq 0) {
                $agnos = [System.Collections.ArrayList]@([int]$actionContext.Configuration.NoAccessPermissionId)
            }


            $body = @{
                Badge = $actionContext.References.Account
                AGNos = $agnos
            }

            $splatRevokeParams = @{
                Uri     = "$($actionContext.Configuration.BaseUrl)/Badges/UpdateBadge"
                Method  = 'POST'
                Headers = $headers
                Body    = ([System.Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json)))
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Revoking Aras-CardAccess permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Reference)]"

                $revokedPermission = Invoke-RestMethod @splatRevokeParams
                if ($revokedPermission.Result -ne 0) {
                    throw $revokedPermission.message
                }
            } else {
                Write-Information "[DryRun] Revoke Aras-CardAccess permission: [$($actionContext.References.Permission.Reference)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Revoke permission [$($actionContext.PermissionDisplayName)] from [$($actionContext.References.Account)] was successful. Action initiated by: [$($actionContext.Origin)]"
                    IsError = $false
                })
        }

        'NotFound' {
            Write-Information "Aras-CardAccess account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Aras-CardAccess account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted. Action initiated by: [$($actionContext.Origin)]"
                    IsError = $false
                })
            break
        }
    }
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Aras-CardAccessError -ErrorObject $ex
        $auditLogMessage = "Could not revoke Aras-CardAccess permission. Error: $($errorObj.FriendlyMessage). Action initiated by: [$($actionContext.Origin)]"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditLogMessage = "Could not revoke Aras-CardAccess permission. Error: $($_.Exception.Message). Action initiated by: [$($actionContext.Origin)]"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $auditLogMessage = $auditLogMessage.substring(0, [System.Math]::Min(254, $auditLogMessage.Length))
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditLogMessage
            IsError = $true
        })
}