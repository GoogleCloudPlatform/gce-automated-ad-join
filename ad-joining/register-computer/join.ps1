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

$metadataUri = "http://metadata.google.internal/computeMetadata/v1/instance";
$metadataHeaders = @{"Metadata-Flavor" = "Google"};

$enableDiagnostics = $false;
try
{
    $enableDiagnostics = (Invoke-RestMethod -Headers $metadataHeaders `
        -Uri "$($metadataUri)/attributes/enable-adjoin-diagnostics");

    if($enableDiagnostics)
    {
        Write-Information -MessageData "AD Join diagnostics: Enabled"; 

        $diagnosticsBucket = (Invoke-RestMethod -Headers $metadataHeaders `
            -Uri "$($metadataUri)/attributes/adjoin-diagnostics-bucket");

        if($diagnosticsBucket -eq "")
        {
            throw New-Object System.ArgumentException "AD Join diagnostics enabled but bucket not set. Point adjoin-diagnostics-bucket metadata to a GCS bucket the service account has write access to.";
        }

        $diagnosticCaptureFile = "$env:SystemRoot\temp\capture.etl";

        if([Environment]::OSVersion.Version -ge (New-Object 'Version' 10,0,17763))
        {
            # Windows Server 2019 and newer
            $version = "ws2019";

            & pktmon start -c --pkt-size 0 -f $diagnosticCaptureFile | Out-Null;
        }
        else
        {
            # Windows Server 2012 R2 or 2016
            $version = "ws2016"

            & netsh trace start capture=yes tracefile=$diagnosticCaptureFile | Out-Null;
        }
    }
}
catch
{
    # Swallow HTTP 404 thrown if metadata key has not been set
    # or if bucket has not been set
    $enableDiagnostics = $false;

    Write-Error -Message "AD Join diagnostics: Failed to start: $($_.Exception.Message)";
}

# Fetch IdToken that we can use to authenticate the instance with.
$IdToken = (Invoke-RestMethod `
    -Headers $metadataHeaders `
    -Uri "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=%scheme%:%2F%2F%domain%%2F&format=full")

# Register computer in Active Directory.
$JoinInfo = try {
    Invoke-RestMethod `
        -Headers @{"Authorization" = "Bearer $IdToken"} `
        -Method POST `
        -Uri "%scheme%://%domain%/"
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
        finally
        {
            if($enableDiagnostics)
            {
                $timestamp = [DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd-HH-mm");

                if($version -eq "ws2019")
                {
                    $diagnosticOutputFile = "$env:SystemRoot\temp\capture.pcapng";
                    & pktmon stop | Out-Null;
                    & pktmon pcapng $diagnosticCaptureFile -o $diagnosticOutputFile | Out-Null;
                }
                else
                {
                    $diagnosticOutputFile = $diagnosticCaptureFile;
                    & netsh trace stop | Out-Null;
                }
                
                $extension = [System.IO.Path]::GetExtension($diagnosticOutputFile);
                $diagnosticBucketFile = "gs://$diagnosticsBucket/captures/$($JoinInfo.ComputerName)-$timestamp$extension";
                & gsutil -q cp $diagnosticOutputFile $diagnosticBucketFile;

                Write-Information -MessageData "AD Join diagnostics: Packet capture copied to $diagnosticBucketFile"; 
            }
        }
    } while ($True)
}
