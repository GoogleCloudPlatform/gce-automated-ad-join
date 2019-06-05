#
# Copyright 2019 Google LLC
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

#--------------------------------------------------------------------------------------------
# Include this scriptlet as specialize script (sysprep-specialize-script-ps1)
# to have VM instances automatically join the domain.
#
# iex((New-Object System.Net.WebClient).DownloadString('https://%domain%/register-computer'))
#--------------------------------------------------------------------------------------------

$ErrorActionPreference = "Stop"

# Fetch IdToken that we can use to authenticate the instance with.
$IdToken = (Invoke-RestMethod `
    -Headers @{"Metadata-Flavor" = "Google"} `
    -Uri "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=https:%2F%2F%domain%%2F&format=full")

# Register computer in Active Directory.
$JoinInfo = (Invoke-RestMethod `
    -Headers @{"Authorization" = "Bearer $IdToken"} `
    -Method POST `
    -Uri "https://%domain%/register-computer")

Write-Host "Successfully registered computer account."
$JoinInfoRedacted = $JoinInfo.PSObject.copy()
$JoinInfoRedacted.ComputerPassword = "*"
$JoinInfoRedacted | Format-List

if ($JoinInfo.ComputerName.Length -gt 15) {
    Write-Host "WARNING: Computer name exceeds NetBIOS limits - domain join might fail"
}

# Join the computer using the computer account that has just been registered.
# Because the join is performed using a known computer password (the one generated
# by the API), it is called an "unsecure join".
#
# If there are multiple domain controllers in the domain, the computer account
# might not have been replicated to all domain controllers yet. To avoid any
# race condition, use the same domain controller for the join as was used
# to create the computer account.

$Credentials = (New-Object pscredential -ArgumentList ([pscustomobject]@{ `
        UserName = $Null
        Password = (ConvertTo-SecureString -String $JoinInfo.ComputerPassword -AsPlainText -Force)[0]}))

$Attempt = 0
do {
    try {
        Add-Computer `
            -ComputerName localhost `
            -Server $JoinInfo.DomainController `
            -DomainName $JoinInfo.Domain `
            -Credential $Credentials `
            -OUPath $JoinInfo.OrgUnitPath `
            -Options UnsecuredJoin,PasswordPass,JoinWithNewName

        Write-Host "Computer successfully joined to domain"
        break
    }
    catch {
        # Authentication occasionally fails after the computer account's password
        # has been reset. In this case, retry.
        $Attempt++
        if ($Attempt -lt 20) {
            Write-Host "Joining computer failed, retry pending: $($_.Exception.Message)"
            Start-Sleep -Seconds 3
        }
        else {
            throw [System.ArgumentException]::new(
                "Joining computer to domain failed: $($_.Exception.Message)")
        }
    }
} while ($True)
