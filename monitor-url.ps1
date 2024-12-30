# Disable SSL validation (for monitoring purposes only)
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy



# List of URLs to monitor
$urls = @(
    "https://example.com",
    "https://expired.badssl.com",
    "https://wrong.host.badssl.com"
)

# Function to check certificate details
function Check-Certificate {
    param (
        [string]$Url
    )
    
    try {
        # Create a web request
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Timeout = 5000 # 5 seconds timeout
        
        # Retrieve the response
        $response = $request.GetResponse()

        # Get the certificate
        $cert = $response.ServicePoint.Certificate
        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert

        # Extract details
        $subject = $cert2.Subject
        $issuer = $cert2.Issuer
        $validFrom = $cert2.NotBefore
        $validTo = $cert2.NotAfter
        $certName = ($subject -split '=')[1]

        # Check expiration
        if ($validTo -lt (Get-Date)) {
            Write-Output "WARNING: Certificate for $Url has expired. Expired on $validTo."
        } else {
            Write-Output "OK: Certificate for $Url is valid until $validTo."
        }

        # Check domain match
        if ($Url -notlike "*$certName*") {
            Write-Output "WARNING: Certificate for $Url does not match the site name ($certName)."
        }
    } catch {
        Write-Output "ERROR: Could not retrieve certificate for $Url. $_"
    }
}

# Loop through each URL and check its certificate
foreach ($url in $urls) {
    Write-Output "Checking $url..."
    Check-Certificate -Url $url
}
