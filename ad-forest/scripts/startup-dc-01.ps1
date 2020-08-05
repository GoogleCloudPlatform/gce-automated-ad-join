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

$AccessToken = (Invoke-RestMethod `
    -Headers @{"Metadata-Flavor" = "Google"} `
    -Uri "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token").access_token

$ProjectId = (Invoke-RestMethod `
    -Headers @{"Metadata-Flavor" = "Google"} `
    -Uri "http://metadata.google.internal/computeMetadata/v1/project/project-id")
    
$DomainName = (Invoke-RestMethod `
    -Headers @{"Metadata-Flavor" = "Google"} `
    -Uri "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ActiveDirectoryDnsDomain")
    
$DomainNetbiosName = (Invoke-RestMethod `
    -Headers @{"Metadata-Flavor" = "Google"} `
    -Uri "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ActiveDirectoryNetbiosDomain")

Write-Host "Reading the DSRM password from secret manager..."
$Secret = (Invoke-RestMethod `
    -Headers @{
        "Metadata-Flavor" = "Google"; 
        "x-goog-user-project" = $ProjectId; 
        "Authorization" = "Bearer $AccessToken"} `
    -Uri "https://secretmanager.googleapis.com/v1beta1/projects/$ProjectId/secrets/dc-dsrm-password/versions/latest:access")
$DsrmPassword = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Secret.payload.data)) 
$DsrmPassword = ConvertTo-SecureString -AsPlainText $DsrmPassword -force

Write-Host "Setting the password for the administrator..."
Set-LocalUser -Name Administrator -Password $DsrmPassword

Write-Host "Setting IP address..."
$IP_this  = (Resolve-DnsName "dc-1.c.$ProjectId.internal").IPAddress
Set-NetIPAddress `
    -InterfaceIndex (Get-NetAdapter -Name Ethernet).InterfaceIndex `
    -IPAddress $IP_this `
    -PrefixLength 24

Write-Host "Creating a new forest for $DomainName ($DomainNetbiosName), making this machine the first DC..."
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $DomainNetbiosName `
    -SafeModeAdministratorPassword $DsrmPassword `
    -DomainMode Win2008R2 `
    -ForestMode Win2008R2 `
    -InstallDns `
    -CreateDnsDelegation:$False `
    -NoRebootOnCompletion:$True `
    -Confirm:$false
    
Write-Host "Configuring DNS settings..."
$IP_other = (Resolve-DnsName "dc-2.c.$ProjectId.internal").IPAddress
Set-DnsClientServerAddress  `
    -InterfaceIndex (Get-NetAdapter -Name Ethernet).InterfaceIndex `
	-ServerAddresses 127.0.0.1,$IP_other

Write-Host "Restarting to apply all settings..."
Restart-Computer