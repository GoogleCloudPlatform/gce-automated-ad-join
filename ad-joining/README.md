# Automatically joining VMs to Active Directory

This repository contains the code of the `register-computer` Cloud Function. This function enables you
to automatically join VM instances to an Active Directory domain.

The code is organized as follows:

* `register-computer/main.py` contains the entry point of the Cloud Function and implements the
   logic for both, joining computers to a domain and scavenging stale computer accounts.
* `register-computer/join.ps1` is the PowerShells script that is deliverered to be run by a
   joining computer while executing the _sysprep specialize_ phase.
* `register-computer/ad/` contains code to connect, search, and create computer accounts in
   Active Directory.
* `register-computer/gcp/` contains code to interact with the Compute Engine API.
* `register-computer/kerberos/` contains code to reset computer account passwords by using a
  helper tool, `ksetpwd`.
* `ksetpwd/` contains the code of a helper tool which uses [MIT Kerberos](https://web.mit.edu/kerberos/)
  to reset account passwords in Active Directory.

## Configuration of the Cloud Function

The `register-computer` obtains its configuration from the environment and supports the following environment variables:

* `AD_DOMAIN` (required): DNS domain used by Active Directory
* `AD_DOMAINCONTROLLER` (optional): Name or IP of domain controller to use. If not specified, the function will locate a domain controller via DNS automatically. This variable should only be used for testing.
* `AD_USERNAME` (required): Username of Active Directory service user. The user must have permission to manage computer objects in the OUs used for automatic domain joining. The value must be provided in `NETBIOS-DOMAIN\SAM-ACCOUNT-NAME` format, UPNs are not supported.
* `AD_PASSWORD` (optional): Clear-text password of Active Directory service user.  This variable should only be used for testing.
* `AD_PASSWORD_CIPHER` (required unless `AD_PASSWORD` is used) Base64-encoded, Cloud KMS-encrypted password of Active Directory service user.
* `CLOUDKMS_KEY` (required unless `AD_PASSWORD` is used): Resource ID of the Cloud KMS key used to encrypt the password. Example: `projects/myproject/locations/global/keyRings/computer-registrar-keyring/cryptoKeys/computer-registrar-key`.
* `PROJECTS_DN`: DN of the OU containing the individual project OUs.

If you run the functional locally, you will need to pass the following, additional environment variables to simulate a
Cloud Functions environment:

* `GOOGLE_APPLICATION_CREDENTIALS` (required for testing): Path to a service account key of a service account that permits the function to interact with Compute Engine. Only required for local testing - when deployed to Cloud Functions, the identity of the service account associated with the function will be used instead.
* `FUNCTION_IDENTITY` (required for testing): Email address of the function's service account.

## Testing locally

### Launching the function

You can run `main.py` locally for testing and debugging purposes:

* Create a new Python virtual environment and activate it.
* Install requirements by running `pip install -r requirements.txt`.
* Configure environment variables.
* Run `main.py`. The function will listen on port 5000 by default.

### Invoking the function

To invoke the function, you need a valid ID Token. To obtain one, launch VM instance and run the following command:

`curl -H "Metadata-Flavor: Google" 'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://127.0.0.1:5000/&format=full'`

Given an ID Token, you can send a request to the function:

`curl -H "Authorization: Bearer [ID Token]" -X POST http://127.0.0.1:5000/`

## License

All files in this repository are under the
[Apache License, Version 2.0](LICENSE.txt) unless noted otherwise.
