##################################################
# HelloID-Conn-Prov-Target-Aras-CardAccess-Delete
# PowerShell V2
##################################################

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
        $action = 'DeleteAccount'
    } else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'DeleteAccount' {
            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Deleting Aras-CardAccess account with accountReference: [$($actionContext.References.Account)]"

                $splatDeleteBadge = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/Badges/BadgeOperation?Facility=$($actionContext.Configuration.Facility)&Badge=$($actionContext.References.Account)&FirstName=$($null)&LastName=$($null)&MI=$($null)&Operation=1"
                    Method  = 'POST'
                    Headers = $headers
                }

                $deletedAccount = Invoke-RestMethod @splatDeleteBadge
                if ($deletedAccount.Result -ne 0) {
                    throw $deletedAccount.message
                }
            } else {
                Write-Information "[DryRun] Delete Aras-CardAccess account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Delete account [$($actionContext.References.Account)] was successful. Action initiated by: [$($actionContext.Origin)]"
                    IsError = $false
                })
            break
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
        $auditLogMessage = "Could not delete Aras-CardAccess account. Error: $($errorObj.FriendlyMessage). Action initiated by: [$($actionContext.Origin)]"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditLogMessage = "Could not delete Aras-CardAccess account. Error: $($_.Exception.Message). Action initiated by: [$($actionContext.Origin)]"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $auditLogMessage = $auditLogMessage.substring(0, [System.Math]::Min(254, $auditLogMessage.Length))
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditLogMessage
            IsError = $true
        })
}