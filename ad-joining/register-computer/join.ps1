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
# iex((New-Object System.Net.WebClient).DownloadString('https://%domain%/'))
#--------------------------------------------------------------------------------------------

$ErrorActionPreference = "Stop"
$InformationPreference = "Continue";

<#
    .SYNOPSIS
        Retrieves the diagnotics bucket from metadata or an empty string if attribute has not been set.

    .OUTPUTS
        [string]

    .EXAMPLE
        $bucket = Get-DiagnosticsBucket
#>
function Get-DiagnosticsBucket
{
    process
    {
        $DiagnosticsBucket = [string]::Empty;

        try
        {
            # Get instance level metadata attribute
            $DiagnosticsBucket = (Invoke-RestMethod -Headers $MetadataHeaders `
                -Uri "$($MetadataUri)/instance/attributes/adjoin-diagnostics-bucket");
        }
        catch
        {
            # Swallow exception that may ocurr when metadata attribute is not set
        }

        if([string]::IsNullOrEmpty($DiagnosticsBucket))
        {
            try
            {
                # Get project level metadata attribute
                $DiagnosticsBucket = (Invoke-RestMethod -Headers $MetadataHeaders `
                    -Uri "$($MetadataUri)/project/attributes/adjoin-diagnostics-bucket");
            }
            catch
            {
                # Swallow exception that may ocurr when metadata attribute is not set
            }
        }
        
        return $DiagnosticsBucket;
    }
}

<#
    .SYNOPSIS
        Determines the version of PktMon

    .OUTPUTS
        Version of PktMon or $Null if PktMon is not available

    .EXAMPLE
        Get-PktMonVersion
#>
function Get-PktMonVersion
{
    process
    {
        $Command = Get-Command -Name "PktMon.exe" -ErrorAction SilentlyContinue;

        if($Null -ne $Command)
        {
            return $Command.Version;
        }

        return $Null;
    }
}

<#
    .SYNOPSIS
        Starts diagnostics depending on whether a bucket was configure or not

    .PARAMETER DiagnosticsBucket
        String denoting the GCS bucket the diagnostics should be copied to

    .EXAMPLE
        Start-JoinDiagnotics -DiagnosticsBucket "adjoin-test";
#>
function Start-JoinDiagnostics
{
    param
    (
        [string] $DiagnosticsBucket
    );

    process
    {
        if(-not [string]::IsNullOrEmpty($DiagnosticsBucket))
        {
            Write-Information -MessageData "AD Join diagnostics: Enabled"; 

            $DiagnosticsCaptureFile = "${env:TEMP}\capture.etl";
            $Version = Get-PktMonVersion;
            
            if($Null -ne $Version)
            {
                if($Version -ge (New-Object Version 10, 0, 17763, 1879))
                {
                    # Use PktMon for tracing
                    & pktmon start -c --pkt-size 0 -f $DiagnosticsCaptureFile | Out-Null;
                }
                else
                {
                    # Fall back to NetEventPacketCapture if only an older version of PktMon is available
                    New-NetEventSession -Name "adjoin" -LocalFilePath $DiagnosticsCaptureFile | Out-Null;
                    Add-NetEventPacketCaptureProvider -SessionName "adjoin" -TruncationLength 0 | Out-Null;
                    
                    foreach($Adapter in (Get-NetAdapter))
                    {
                        Add-NetEventNetworkAdapter -Name "$($Adapter.Name)" | Out-Null;
                    }

                    Start-NetEventSession -Name "adjoin";
                }
            }
            else
            {
                # PktMon does not exist in this version of Windows or does not provide trace recording, falling back to netsh trace
                & netsh trace start capture=yes perfMerge=no report=disabled tracefile=$DiagnosticsCaptureFile | Out-Null;
            }
        }
        else
        {
            Write-Information -Message "AD Join diagnostics: Not enabled";
        }
    }
}

<#
    .SYNOPSIS
        Stops diagnostics depending on whether a bucket was configure or not

    .PARAMETER DiagnosticsBucket
        String denoting the GCS bucket the diagnostics should be copied to

    .EXAMPLE
        Stop-JoinDiagnotics -DiagnosticsBucket "adjoin-test";
#>
function Stop-JoinDiagnostics
{
    param
    (
        [string] $DiagnosticsBucket
    );

    process
    {
        if(-not [string]::IsNullOrEmpty($DiagnosticsBucket))
        {
            $DiagnosticsCaptureFile = "${env:TEMP}\capture.etl";
            $DiagnosticsOutputFile = $DiagnosticsCaptureFile;
            $Timestamp = [DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd-HH-mm");

            $Version = Get-PktMonVersion;
            if($Null -ne $Version)
            {
                if($Version -ge (New-Object Version 10, 0, 17763, 1879))
                {
                    # Stop PktMon trace and convert to pcapng
                    $DiagnosticsOutputFile = "$env:SystemRoot\temp\capture.pcapng";
                    & pktmon stop | Out-Null;
                    & pktmon pcapng $DiagnosticsCaptureFile -o $DiagnosticsOutputFile | Out-Null;
                }
                else
                {
                    # Stop NetEventPacketCapture trace
                    Stop-NetEventSession -Name "adjoin";
                    Remove-NetEventSession -Name "adjoin";
                }
            }
            else
            {
                # Stop netsh trace
                & netsh trace stop | Out-Null;
            }
            
            $Extension = [System.IO.Path]::GetExtension($DiagnosticsOutputFile);
            $DiagnosticsBucketFile = "gs://$DiagnosticsBucket/captures/$($JoinInfo.ComputerName)-$Timestamp$Extension";
            & gsutil -q cp $DiagnosticsOutputFile $DiagnosticsBucketFile;

            Write-Information -MessageData "AD Join diagnostics: Packet capture copied to $DiagnosticsBucketFile"; 
        }
    }
}

$MetadataUri = "http://metadata.google.internal/computeMetadata/v1";
$MetadataHeaders = @{"Metadata-Flavor" = "Google"};

# Retrieve diagnostics bucket from metadata
$DiagnosticsBucket = Get-DiagnosticsBucket;

# Diagnostics started depending on bucket setting
Start-JoinDiagnostics -DiagnosticsBucket $DiagnosticsBucket;

# Fetch IdToken that we can use to authenticate the instance with.
$IdToken = (Invoke-RestMethod `
    -Headers $MetadataHeaders `
    -Uri "$($MetadataUri)/instance/service-accounts/default/identity?audience=%scheme%:%2F%2F%domain%%2F&format=full")

# Determine AD site
$AdSite = "";
try
{
    $Result = & nltest /dsgetdc:%ad_domain% /DS_6 /TRY_NEXT_CLOSEST_SITE;
    $PatternMatches = ($Result | Select-String -Pattern "^Our Site Name: (.+)$").Matches;
    
    if($Null -ne $PatternMatches)
    {
        $AdSite = $PatternMatches.Groups[1].Value;
    }
}
catch
{
    # Swallow exception and continue without site-awareness
}

if([string]::IsNullOrEmpty($AdSite))
{
    Write-Host "AD site-awareness: Failed to determine closest AD site";
}
else
{
    Write-Host "AD site-awareness: Using site '$AdSite' for join";
}

# Register computer in Active Directory.
$JoinInfo = try {
    Invoke-RestMethod `
        -Headers @{"Authorization" = "Bearer $IdToken"} `
        -Method POST `
        -Uri "%scheme%://%domain%/?ad_site=$AdSite"
 } catch {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $errorObject = $reader.ReadToEnd() | ConvertFrom-Json

    Write-Host $_.Exception.Message 
    Write-Host "Error is:" $errorObject.error
    Write-Host "Failed to register computer account."
}

if ($JoinInfo) {
    Write-Host "Successfully registered computer account."
    $JoinInfoRedacted = $JoinInfo.PSObject.copy()
    $JoinInfoRedacted.ComputerPassword = "*"
    $JoinInfoRedacted | Format-List

    $NewComputerName = $JoinInfo.ComputerName
    $OriginalComputerName = $JoinInfo.OriginalComputerName

    if ($NewComputerName -ne $OriginalComputerName) {
        Write-Host "Renaming computer from $OriginalComputerName to $NewComputerName"
        Rename-Computer -ComputerName localhost -NewName $NewComputerName -Force -PassThru -Verbose
    }

    if ($NewComputerName.Length -gt 15) {
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
                -Options UnsecuredJoin,PasswordPass,JoinWithNewName `
                -Force

            Write-Host "Computer successfully joined to domain"
            Stop-JoinDiagnostics -DiagnosticsBucket $DiagnosticsBucket;
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
                Stop-JoinDiagnostics -DiagnosticsBucket $DiagnosticsBucket;

                throw [System.ArgumentException]::new(
                    "Joining computer to domain failed: $($_.Exception.Message)")
            }
        }
    } while ($True)
}
