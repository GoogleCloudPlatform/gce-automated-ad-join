#
# Copyright 2020 Google LLC
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

$ErrorActionPreference = "stop"

if ((Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -eq 2) {
    # This machine has been promoted to a domain controller already, do not run script again.
    exit
}

Write-Host "Reading the DSRM password from secret manager..."
$AccessToken = (Invoke-RestMethod `
    -Headers @{"Metadata-Flavor" = "Google"} `
    -Uri "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token").access_token

$ProjectId = (Invoke-RestMethod `
    -Headers @{"Metadata-Flavor" = "Google"} `
    -Uri "http://metadata.google.internal/computeMetadata/v1/project/project-id")

$DomainName = (Invoke-RestMethod `
    -Headers @{"Metadata-Flavor" = "Google"} `
    -Uri "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ActiveDirectoryDnsDomain")

$Secret = (Invoke-RestMethod `
    -Headers @{
        "Metadata-Flavor" = "Google"; 
        "x-goog-user-project" = $ProjectId; 
        "Authorization" = "Bearer $AccessToken"} `
    -Uri "https://secretmanager.googleapis.com/v1beta1/projects/$ProjectId/secrets/dc-dsrm-password/versions/latest:access")
$DsrmPassword = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Secret.payload.data))
$DsrmPassword = ConvertTo-SecureString -AsPlainText $DsrmPassword -force

Write-Host "Waiting for first DC to become ready"
$DomainIsReady=$False
for ($i=0; $i -le 15; $i++) {
    & nltest /dsgetdc:$DomainName | Out-Null
    if($LASTEXITCODE -ne 0) {
        Write-Host "Domain not ready, waiting 1 more minute..."
        Start-Sleep -s 60
    }
    else {
        $DomainIsReady=$True
        Write-Host "Domain controller is reachable"
        break
    }
}

if($DomainIsReady -eq $False) {
    Write-Host "Domain not ready, giving up"
    exit 1
}

Write-Host "Setting the password for the administrator..."
Set-LocalUser -Name Administrator -Password $DsrmPassword

Write-Host "Setting IP address..."
$IP_this  = (Resolve-DnsName "dc-2.c.$ProjectId.internal").IPAddress
Set-NetIPAddress `
    -InterfaceIndex (Get-NetAdapter -Name Ethernet).InterfaceIndex `
    -IPAddress $IP_this `
    -PrefixLength 24
    
Write-Host "Adding computer as domain controller to $DomainName..."
Install-ADDSDomainController `
    -DomainName $DomainName `
	-SafeModeAdministratorPassword $DsrmPassword `
    -InstallDns `
	-Credential (New-Object System.Management.Automation.PSCredential ("Administrator@$DomainName", $DsrmPassword)) `
	-NoRebootOnCompletion:$true  `
    -Confirm:$false

Write-Host "Configuring DNS settings..."
$IP_other = (Resolve-DnsName "dc-1.c.$ProjectId.internal").IPAddress
Set-DnsClientServerAddress  `
    -InterfaceIndex (Get-NetAdapter -Name Ethernet).InterfaceIndex `
	-ServerAddresses 127.0.0.1,$IP_other

Write-Host "Restarting to apply all settings..."
Restart-Computer