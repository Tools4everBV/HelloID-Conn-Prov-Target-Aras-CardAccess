#################################################
# HelloID-Conn-Prov-Target-Aras-CardAccess-Create
# PowerShell V2
#################################################

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
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

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

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.AccountField
        $correlationValue = $actionContext.CorrelationConfiguration.PersonFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }

        $splatGetBadge = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/Badges/BadgeInfo?$($correlationField)=$($correlationValue)&Facility=$($actionContext.Configuration.Facility)"
            Method  = 'Get'
            Headers = $headers
        }
        $correlatedAccount = Invoke-RestMethod @splatGetBadge
    }

    if ($correlatedAccount.Count -eq 0) {
        $action = 'CreateAccount'
    } elseif ($correlatedAccount.Count -eq 1) {
        $action = 'CorrelateAccount'
    } elseif ($correlatedAccount.Count -gt 1) {
        throw "Multiple accounts found for person where $correlationField is: [$correlationValue]"
    }

    # Process
    switch ($action) {
        'CreateAccount' {
            # Add facility to body and set properties to create disabled account
            $actionContext.Data | Add-Member @{
                Facility = $actionContext.Configuration.Facility
                Enabled  = 0
                ActvDate = $null
                ExprDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }

            $splatCreateParams = @{
                Uri     = "$($actionContext.Configuration.BaseUrl)/Badges/AddBadge"
                Method  = 'POST'
                Headers = $headers
                Body    = ([System.Text.Encoding]::UTF8.GetBytes(($actionContext.Data | ConvertTo-Json)))
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information 'Creating and correlating Aras-CardAccess account'

                $createdAccount = Invoke-RestMethod @splatCreateParams
                if ($createdAccount.Result -ne 0) {
                    throw $createdAccount.message
                }

                # Cast to int for reconciliation purposes and logging in HelloID
                $outputContext.data.Badge = [int]$outputContext.data.Badge
                $outputContext.Data = ($outputContext.data | Select-Object -Property $outputContext.data.PSObject.Properties.Name)
                $outputContext.AccountReference = [int]$outputContext.data.Badge
            } else {
                Write-Information '[DryRun] Create and correlate Aras-CardAccess account, will be executed during enforcement'
            }
            $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]"
            break
        }

        'CorrelateAccount' {
            Write-Information 'Correlating Aras-CardAccess account'
            $correlatedAccount | Add-Member -MemberType NoteProperty -Name 'FirstName' -Value $correlatedAccount.FrstName

            $outputContext.Data = ($correlatedAccount | Select-Object -Property $outputContext.data.PSObject.Properties.Name)
            $outputContext.AccountReference = $correlatedAccount.Badge
            $outputContext.AccountCorrelated = $true
            $auditLogMessage = "Correlated account: [$($outputContext.AccountReference)] on field: [$($correlationField)] with value: [$($correlationValue)]"
            break
        }
    }

    $outputContext.success = $true
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = $action
            Message = $auditLogMessage
            IsError = $false
        })
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Aras-CardAccessError -ErrorObject $ex
        $auditLogMessage = "Could not create or correlate Aras-CardAccess account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditLogMessage = "Could not create or correlate Aras-CardAccess account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $auditLogMessage = $auditLogMessage.substring(0, [System.Math]::Min(254, $auditLogMessage.Length))
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditLogMessage
            IsError = $true
        })
}