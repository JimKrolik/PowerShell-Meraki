<#	
	.NOTES
	===========================================================================
	 Created by:	James Krolik
	 Created on:   	08/01/2022
	 Updated on:	08/01/2022
	 Filename:     	Meraki-API-Functions.ps1
	===========================================================================
	.DESCRIPTION
	This script is a dump of functions I've built for managing Meraki clients to ensure consistency.
	Originally, this was built to ensure that all of our clients had the API enabled, SAML enabled,
	the certificate thumbprint installed for SAML, and the SAML role created.  

	It has since evolved to include other items, so I felt this would be a good starting point for anyone
	wanting to learn about interacting with Meraki's v1 API with PowserShell.  If new functions are needed, 
  they should be able to be adapted from Meraki's API documentation.

	Configurations that should be done prior to executing:
	Add your API key
	Add your certificate thumbprint if using SAML
	
	The functional workflow of this script is as follows:
	
		Get all organizations
		Check if API management is enabled and enable if it is not.
		Check if SAML is enabled and enable it if it is not.
		Check if a certificate thumbprint exists and compare with the newCertificateThumbprint.
		Update the certificate if they do not match.
		Check if our account is in the SAML group and add it if it is missing.
		Finally, loop through and add our new admin account to all clients if it is not present.
    
#>

cls

#The API key will be for the main administrator account.
$apiKey = ""	# <== Enter your API key here

#This will be the thumbprint we want to standardize on.
$newCertificateThumbprint = ""  # <== Enter your certificate thumbprint here in the format AA:BB:CC...

#If you are using SAML change this to whatever you want the acocunt to be called.
$samlGroupName = "_yourSAMLname_"

#If you are going to add a new admin to every group, change the parameters here.
$newAdminName = ""
$newAdminEmail = ""


$headers = @{
    "X-Cisco-Meraki-API-Key"=$apiKey
    "Content-Type" = "application/json"
    }

<#################
## API Functions #
##################>

function isAPIEnabled() {
<#
This function is used to query the organization to see if API is enabled or not.
When called, it returns the boolean of whether or not it is enabled.
#>
    Param (         
        [Parameter(Mandatory=$true)]
        [String]$id
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id"
        "Method" = 'GET'
    }
    $apicheck = Invoke-RestMethod @Params -headers $headers
    return $apicheck.api.enabled
}

function enableAPI() {
<#
This function is called when we want to enable the API on a client that is not currently set on.
#>
    Param (
        [Parameter(Mandatory=$true)]
        [String]$id
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id"
        "Method" = 'PUT'
    }

    #Construct our body for sending the updated settings.
    $body = @{
        "api" = @{ "enabled" = $true };
    };

    #Convert to JSON as needed and invoke the request.
    $jsonbody = $body | ConvertTo-Json
    $apicheck = Invoke-RestMethod @Params -headers $headers -body $jsonbody
}

<##################
## SAML Functions #
###################>

function isSAMLEnabled() {
<#
This function is used to query the organization to see if SAML is enabled or not.
When called, it returns the boolean of whether or not it is enabled.
#>
    Param (   
        [Parameter(Mandatory=$true)]
        [String]$id
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/saml"
        "Method" = 'GET'
    }

    $samlCheck = Invoke-RestMethod @Params -headers $headers
    return $samlCheck.enabled

}

function enableSAML() {
<#
This function is used to enable the SAML when called.
#>
    Param (      
        [Parameter(Mandatory=$true)]
        [String]$id
        )
    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/saml"
        "Method" = 'PUT'
    }

    #Construct our body for sending the updated settings.
    $body = @{
        "enabled" = $true
    };

    #Convert to JSON as needed and invoke the request.
    $jsonbody = $body | ConvertTo-Json
    Invoke-RestMethod @Params -headers $headers -body $jsonbody
}

function addToSAML() {
<#
This function is used to add a SAML role and grant 'full' tenant access.
#>
    Param (    
        [Parameter(Mandatory=$true)]
        [String]$id
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/samlRoles"
        "Method" = 'POST'
    }

    #Construct our body for sending the updated settings.  
    $body = @{
        "role" = $samlGroupName
        "orgAccess" = "full"
    };

    #Convert to JSON as needed and invoke the request.
    $jsonbody = $body | ConvertTo-Json

    Invoke-RestMethod @Params -headers $headers -body $jsonbody
    write-host "Added $samlGroupName to SAML database."

}

function checkIfGroupIsInSAML() {
<#
This function is used to check if $samlGroupName is in the SAML administrators group.
#>
    Param (      
        [Parameter(Mandatory=$true)]
        [String]$id
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/samlRoles"
        "Method" = 'GET'
    }

     $isInSAML = Invoke-RestMethod @Params -headers $headers
     if ($isInSAML.role -contains $samlGroupName) {
        return $true
     }
     else {
        return $falase
     }
}

<#################
## IDP Functions #
##################>

function getIdpId() {
<#
This function will return the SAML idpID required for updating the certificate fingerprint.
#>  
    Param ( 
        [Parameter(Mandatory=$true)]
        [String]$id
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/saml/idps"
        "Method" = 'GET'
    }

    $idps = Invoke-RestMethod @Params -headers $headers
    return $idps.idpId

}

function createIdpId() {
<#
This function will create the idpId and inject the certificate fingerprint at the same time.
#>
    Param (         
        [Parameter(Mandatory=$true)]
        [String]$id,
        [Parameter(Mandatory=$true)]
        [String]$cert
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/saml/idps"
        "Method" = 'POST'
    }

    #Construct our body for sending the updated settings.
    $body = @{
        "x509certSha1Fingerprint" = $cert
    };

    #Convert to JSON as needed and invoke the request.
    $jsonbody = $body | ConvertTo-Json
    Invoke-RestMethod @Params -headers $headers -body $jsonbody
}

function addCertificateThumbprint() {
<#
This function will update the Certificate Thumbprint
#>
    Param (          
        [Parameter(Mandatory=$true)]
        [String]$id,
        [Parameter(Mandatory=$true)]
        [String]$cert,
        [Parameter(Mandatory=$true)]
        [String]$idpId
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/saml/idps/$idpId"
        "Method" = 'PUT'
    }

    #Construct our body for sending the updated settings.
    $body = @{
        "x509certSha1Fingerprint" = $cert
    };

    #Convert to JSON as needed and invoke the request.
    $jsonbody = $body | ConvertTo-Json
    Invoke-RestMethod @Params -headers $headers -body $jsonbody
}

function getCertificateThumbprint() {
<#
This function will return the current Certificate Thumbprint
#>
    Param (           
        [Parameter(Mandatory=$true)]
        [String]$id
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/saml/idps"
        "Method" = 'GET'
    }

    $certificate = Invoke-RestMethod @Params -headers $headers
    return $certificate.x509certSha1Fingerprint
}

<###################
# Admin Management #
###################>
function getOrganizationAdmins() {
<#
This function will return all of the organization admins for an organization.
#>  
    Param ( 
        [Parameter(Mandatory=$true)]
        [String]$id
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/admins"
        "Method" = 'GET'
    }

    $orgAdmins = Invoke-RestMethod @Params -headers $headers
    return $orgAdmins

}

function addOrganizationAdmins() {
<#
This function will return all of the organization admins for an organization.
#>  
    Param (    
        [Parameter(Mandatory=$true)]
        [String]$id
        )

    $Params = @{
        "URI" = "https://api.meraki.com/api/v1/organizations/$id/admins"
        "Method" = 'POST'
    }

    #Construct our body for sending the updated settings.
    $body = @{
        "name" = $newAdminName
        "email" = $newAdminEmail
        "orgAccess" = "full"     
    };

    #Convert to JSON as needed and invoke the request.
    $jsonbody = $body | ConvertTo-Json

    Invoke-RestMethod @Params -headers $headers -body $jsonbody
    write-host "Added $newAdminEmail to organization administrators."

}

<################
# Program Begin #
################>

#Get list of organizations
$Params = @{
    "URI" = "https://api.meraki.com/api/v1/organizations"
    "Method" = 'GET'
    }

$listOfOrgs = Invoke-RestMethod @Params -headers $headers

#Loop through each organization.
$listOfOrgs.ForEach({

write-host "Org ID: " $_.id
write-host "Org Name: " $_.name

    #Check if API is enabled.
    $isAPIEnabled = isAPIEnabled -id $_.id

    write-host "API:  " $isAPIEnabled
    if ($isAPIEnabled -eq $true) {

        #Check if SAML is enabled
        $isSAMLEnabled = isSAMLEnabled -id $_.id
        write-host "SAML: " $isSAMLEnabled

        if ($isSAMLEnabled -eq $true) {
            #Get the certificate thumbprint and output if present.
            $certificateThumbprint = getCertificateThumbprint -id $_.id
            write-host "Certificate Thumbprint: " $certificateThumbprint
            write-host ""
        }

        else {
            #Verbose output if SAML isn't enabled and then call the function to enable it.
            write-warning "Please enable SAML to query certificate thumbprint."
            write-host "Attempting to enable SAML."
            write-host ""

            enableSAML -id $_.id 
        }
    
        #Get the certificate thumbprint
        $certificateThumbprint = getCertificateThumbprint -id $_.id

        #If the thumbprint is not set, alert and do a further check to attempt to correct it.
        if ($certificateThumbprint -eq $null) {

            write-warning "No certificate thumbprint found"
            write-host "Attempting to update thumbprint."

            #In order to see if the thumbprint is just not set or if the whole section is disabled, check for the presence of
            #an IDP attribute
            $idpId = getIdpId -id $_.id

            $id = $_.id
                try { 
                    #Attempt to add and if it fails, then the IDP is not set, so catch the error and create it.
                    addCertificateThumbprint -id $id -cert $newCertificateThumbprint -idpID $idpId
                    }
                catch {
                     createIdpId -id $id -cert $newCertificateThumbprint
                 }
       } #end certificateThumbprint $null check.

    } #end isAPIEnabled Check

    else { #API is currently not enabled.  Verbose output and attempt to enable it.
        write-warning "Please enable API to query SAML."
        write-host "Attempting to enable API."

        enableAPI -id $_.id

        write-warning "API needs to be enabled in order to query certificate thumbprint."
        write-host ""
    }

    #Now that we've made it this far, check if your SAML group is NOT present in the roles for the SAML database, and if not, add it.
    if (!(checkIfGroupIsInSAML -id $_.id)) {
        write-warning "$samlGroupName is not in the SAML database for this client."
        addToSAML -id $_.id
        write-host ""
    }

    #Add new admin account as an organizational admin.
    $orgAdmins = getOrganizationAdmins -id $_.id

    write-host "List of Admins:"

    $accountToAddFound = $false

    try { #Enumerate each administrator in the list.  This will throw an error if only one exists, hence the try statement.
    
            $orgAdmins.ForEach({

            $email = $_.email

            if ($email -eq $newAdminEmail) {
                $accountToAddFound = $true
            }

        })

    }

    catch { #If we catch, there is only one administrator, so perform the check for adding.
	
	if ($orgAdmins.email -eq $newAdminEmail) {
		$accountToAddFound = $true
	}

    }
    write-host " "

    if ($accountToAddFound -eq $false) {
        write-host "Adding new admin account Account"
        addOrganizationAdmins -id $_.id
        $accountToAddFound = $false
        
    }

})
