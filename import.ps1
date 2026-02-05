#################################################
# HelloID-Conn-Prov-Target-Aras-CardAccess-Import
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
    Write-Information 'Starting Aras-CardAccess account entitlement import'

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

    foreach ($importedAccount in $importedAccounts) {
        # Making sure only fieldMapping fields are imported
        $importedAccount | Add-Member -MemberType NoteProperty -Name 'FirstName' -Value $importedAccount.FrstName
        $data = @{}
        foreach ($field in $actionContext.ImportFields) {
            $data[$field] = $importedAccount.$field
        }

        # Set Enabled based on importedAccount status
        $isEnabled = $false
        if ($importedAccount.Enabled -eq $true) {
            $now = Get-Date
            $activeDate = $null
            if ($null -ne $importedAccount.actvDate) {
                $activeDate = Get-Date $importedAccount.actvDate
            }
            $expireDate = $null
            if ($null -ne $importedAccount.ExprDate) {
                $expireDate = Get-Date $importedAccount.ExprDate
            }

            if (((-not $activeDate) -or $activeDate -le $now) -and ((-not $expireDate) -or $expireDate -ge $now)) {
                $isEnabled = $true
            }
        }

        # Make sure the displayName has a value
        $displayName = "$($importedAccount.FirstName) $($importedAccount.LastName)".trim()
        if ([string]::IsNullOrEmpty($displayName)) {
            $displayName = $importedAccount.badge
        }

        # Return the result
        Write-Output @{
            AccountReference = $importedAccount.badge
            displayName      = $displayName
            UserName         = "$($importedAccount.badge)"
            Enabled          = $isEnabled
            Data             = $data
        }
    }
    Write-Information 'Aras-CardAccess account entitlement import completed'
} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Aras-CardAccessError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import Aras-CardAccess account entitlements. Error: $($errorObj.FriendlyMessage)"
    } else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import Aras-CardAccess account entitlements. Error: $($ex.Exception.Message)"
    }
}