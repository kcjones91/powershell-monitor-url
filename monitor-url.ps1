function Get-CertificateDetails {
    param (
        [string]$Hostname,
        [int]$Port = 443
    )

    try {
        # Create a TCP connection to the server
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($Hostname, $Port)

        # Create an SSL stream to retrieve the certificate
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true })
        $sslStream.AuthenticateAsClient($Hostname)

        # Get the certificate
        $cert = $sslStream.RemoteCertificate
        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert

        # Extract details
        $details = @{
            Hostname       = $Hostname
            Subject        = $cert2.Subject
            Issuer         = $cert2.Issuer
            ValidFrom      = $cert2.NotBefore
            ValidTo        = $cert2.NotAfter
            Thumbprint     = $cert2.Thumbprint
        }

        # Close connections
        $sslStream.Close()
        $tcpClient.Close()

        return $details
    } catch {
        Write-Output "ERROR: Could not retrieve certificate for $Hostname. Exception: $_"
    }
}

# List of URLs to monitor
$urls = @(
    "example.com",
    "expired.badssl.com",
    "wrong.host.badssl.com"
)

# Loop through each URL and get certificate details
foreach ($url in $urls) {
    Write-Output "Checking $url..."

    # Fetch certificate details
    $certDetails = Get-CertificateDetails -Hostname $url

    if ($certDetails) {
        Write-Output "Certificate Details for $url:"
        Write-Output $certDetails
        Write-Output ""

        # Additional checks
        if ($certDetails.ValidTo -lt (Get-Date)) {
            Write-Output "WARNING: Certificate for $url has expired. Expired on $($certDetails.ValidTo)."
        } else {
            Write-Output "OK: Certificate for $url is valid until $($certDetails.ValidTo)."
        }
    }
}
