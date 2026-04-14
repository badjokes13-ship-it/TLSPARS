
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$exportCsv = "D:\forensics\UpdateCertResults_$timestamp.csv"
$exportJson = "D:\forensics\UpdateCertResults_$timestamp.json"
$trustedMicrosoftRoots = @(
    "Microsoft Root Certificate Authority 2011",
    "Microsoft Root Certificate Authority 2010",
    "Microsoft ECC Root Certificate Authority 2017",
    "Microsoft ECC Product Root Certificate Authority 2018"
)

$verboseOutput = $true
$probeResults = @()

# -------------------- Caches for API lookups --------------------
$geoCache = @{}
$asnCache = @{}
$whoisCache = @{}
function Get-GeoInfo {
    param([string]$ip)
    if ($geoCache.ContainsKey($ip)) { return $geoCache[$ip] }

    try {
        $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -ErrorAction Stop
        $entry = @{ City = $geo.city; Country = $geo.country; ISP = $geo.isp; Org = $geo.org }
    }
    catch {
        $entry = @{ City = "-"; Country = "-"; ISP = "-"; Org = "-" }
    }
    $geoCache[$ip] = $entry
    return $entry
}
 
# Helper to normalize ASN to AS<number>
function Normalize-Asn {
    param([string]$raw)
    if (-not $raw) { return "" }
    $digits = ($raw -replace '[^\d]', '')
    if ($digits -match '^\d+$') { return "AS$digits" }
    return $raw
}

function Get-ASNInfo {
    param([string]$ip)
    if ($asnCache.ContainsKey($ip)) { return $asnCache[$ip] }

    try {
        $asn = Invoke-RestMethod -Uri "https://ipinfo.io/$ip/json" -ErrorAction Stop
        $entry = $asn.org
        $entry += $asn.ASN
    }
    catch {
        $entry = "-"
    }
    $asnCache[$ip] = $entry
    return $entry
}

function Get-WhoisInfo {
    param([string]$ip)
    if ($whoisCache.ContainsKey($ip)) { return $whoisCache[$ip] }

    $sources = @(
        "https://rdap.arin.net/registry/ip/",
        "https://rdap.db.ripe.net/ip/",
        "https://rdap.apnic.net/ip/",
        "https://rdap.lacnic.net/rdap/ip/",
        "https://rdap.afrinic.net/rdap/ip/"
    )

    foreach ($uri in $sources) {
        try {
            $whois = Invoke-RestMethod -Uri "$uri$ip" -ErrorAction Stop
            $vcard = $whois.entities[0].vcardArray[1]
            $address = ($vcard | Where-Object { $_[0] -eq 'adr' })[0][1][3..5] -join ', '
            $contact = ($vcard | Where-Object { $_[0] -eq 'tel' })[0][1]
            $entry = @{ Name = $whois.name; Handle = $whois.handle; Address = $address; Contact = $contact }
            $whoisCache[$ip] = $entry
            return $entry
        }
        catch {
            continue
        }
    }

    $entry = @{ Name = "-"; Handle = "-"; Address = "-"; Contact = "-" }
    $whoisCache[$ip] = $entry
    return $entry
}

function Validate-CatalogChain {
    param([string]$leafThumb)
    return "Skipped"
}

function Score-Provenance {
    param(
        [string]$issuer,
        [string]$subject,
        [string]$targetHost,
        [bool]  $chainComplete,
        [bool]  $isRegistry
    )
    return 0
}


function Resolve-TargetIPs {
    param([string]$Hostname)
    $ips = @()
    foreach ($rtype in "A", "AAAA") {
        try {
            $ips += Resolve-DnsName -Name $Hostname -Type $rtype -ErrorAction Stop |
                Where-Object IPAddress | Select-Object -ExpandProperty IPAddress
        }
        catch {
            Write-VerboseLog " No $rtype record for $Hostname"
        }
    }
    return $ips
}
function Perform-TLSProbe {
    param(
        [string]$IP,
        [string]$TargetHost,
        [string]$IPVersion
    )
    $ipObj = [System.Net.IPAddress]::Parse($IP)
    if ($ipObj.IsIPv6) {
        # IPv6 logic 
        Write-Host "IPV6 probe for $IP - skipping in this implementation"
        break 
    }
    $result = @{
        ChainBuilt                 = $false
        LeafCert                   = $null
        Chain                      = @()
        TLSVersion                 = "-"
        CipherSuite                = "-"
        CertSubject                = "-"
        Issuer                     = "-"
        ValidTo                    = "-"
        ValidFrom                  = "-"
        Thumbprint                 = "-"
        RootCertIssuer             = "-"
        RootCertThumbprint         = "-"
        HostnameMatch              = "-"
        IssuerTrustStatus          = "-"
        TimestampESN               = "-"
        ESNStatus                  = "-"
        CatalogChainValidation     = "-"
        CatalogValidationAttempted = $false
        ProvenanceScore            = 0
        ChainProvenance            = @()
        Error                      = $null
    }

    $tcp = $null
    $ssl = $null

    try {
        $tcp = if ($IPVersion -eq "IPv6") {
            [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        }
        else {
            [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
        }

        $async = $tcp.BeginConnect($IP, 443, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) {
            throw "TCP timeout to $IP"
        }
        $tcp.EndConnect($async)

        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })

        try {
            $ssl.AuthenticateAsClient(
                $TargetHost,
                $null,
                [System.Security.Authentication.SslProtocols]::Tls12 -bor
                [System.Security.Authentication.SslProtocols]::Tls13,
                $false
            )
        }
        catch {
            $result.Error = "SSPI failure: $($_.Exception.Message)"
            if ($_.Exception.InnerException) {
                $result.Error += " | Inner: $($_.Exception.InnerException.Message)"
            }
            throw "TLS handshake failed"
        }

        $leafCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        $built = $chain.Build($leafCert)

        $result.ChainBuilt = $built
        $result.LeafCert = $leafCert
        $result.Chain = $chain.ChainElements
        $result.TLSVersion = $ssl.SslProtocol.ToString()
        $result.CipherSuite = $ssl.CipherAlgorithm.ToString()
        $result.CertSubject = $leafCert.Subject
        $result.Issuer = $leafCert.Issuer
        $result.ValidTo = $leafCert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
        $result.ValidFrom = $leafCert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss")
        $result.Thumbprint = $leafCert.Thumbprint

        # Root cert extraction
        $rootCert = $chain.ChainElements[-1].Certificate
        $result.RootCertIssuer = $rootCert.Subject
        $result.RootCertThumbprint = $rootCert.Thumbprint

        # Hostname match via SAN
        $sanExt = $leafCert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
        $sanList = if ($sanExt) { $sanExt.Format($false) -split ",\s*" } else { @() }
        $result.HostnameMatch = if (
            $leafCert.Subject -match [regex]::Escape($TargetHost) -or
            ($sanList | Where-Object { $_ -match [regex]::Escape($TargetHost) })
        ) { "Match" } else { "Mismatch" }

        # Issuer trust scoring
        $trustedMicrosoftRoots = @(
            "*Microsoft*",
            "*DigiCert Global Root G2*",
            "*DigiCert Global Root CA*"
        )

        if ($result.ASN -like "*AS8075*" -and
            ($trustedMicrosoftRoots | Where-Object { $rootCert.Subject -like $_ })) {
            $result.IssuerTrustStatus = "Microsoft-Trusted"
        }
        else {
            $result.IssuerTrustStatus = "Non-Microsoft"
        }

        # ESN extraction via OID
        $esnExt = $leafCert.Extensions | Where-Object {
            $_.Oid.Value -eq "1.3.6.1.4.1.311.2.1.27"
        }

        $result.TimestampESN = if ($esnExt) {
            try {
                $rawBytes = $esnExt.RawData
                if ($rawBytes.Length -gt 0) {
                    [System.Text.Encoding]::UTF8.GetString($rawBytes)
                }
                else {
                    "Present (empty)"
                }
            }
            catch {
                "Present (undecodable)"
            }
        }
        else {
            "-"
        }

        $result.ESNStatus = if ($result.TimestampESN -eq "-") { "Missing" } else { "Present" }

        # Chain provenance
        $result.ChainProvenance = foreach ($elem in $chain.ChainElements) {
            $c = $elem.Certificate
            $ekuExt = $c.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
            $ekuVal = if ($ekuExt) { $ekuExt.Format($false) } else { "" }
            [PSCustomObject]@{
                Subject      = $c.Subject
                Issuer       = $c.Issuer
                Thumbprint   = $c.Thumbprint
                NotBefore    = $c.NotBefore
                NotAfter     = $c.NotAfter
                SerialNumber = $c.SerialNumber
                EKU          = $ekuVal
            }
        }

        # Catalog validation
        $result.CatalogValidationAttempted = $true

        if ($result.CatalogValidationAttempted) {
            try {
                $result.CatalogChainValidation = Validate-CatalogChain -leafThumb $leafCert.Thumbprint
            }
            catch {
                Write-VerboseLog " Catalog validation failed: $_"
                $result.CatalogChainValidation = "Error"
            }
        }
        else {
            Write-VerboseLog " Skipping catalog validation: ESN not present"
            $result.CatalogChainValidation = "Skipped"
        }

        # Provenance scoring
        $result.ProvenanceScore = Score-Provenance `
            -issuer $rootCert.Subject `
            -subject $leafCert.Subject `
            -targetHost $TargetHost `
            -chainComplete $built `
            -isRegistry ($registryHostnames -contains $TargetHost)

    }
    catch {
        Write-Warning "TLS probe failed for $IP : $_"
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Close() }
    }

    return $result
}



function Extract-CertMetadata {
    param([hashtable]$TLSResult, [string]$TargetHost)

    $leafCert = $TLSResult.LeafCert

    $chain = $TLSResult.Chain

    if (-not $leafCert) {
        return @{
            LeafCertSubject    = "-"
            LeafCertThumbprint = "-"
            RootCertIssuer     = "-"
            RootCertThumbprint = "-"
            HostnameMatch      = "-"
            IssuerTrustStatus  = "-"
            TimestampESN       = "-"
            ChainDetails       = @()
        }
    }

    $leafSubject = $leafCert.Subject
    $leafThumbprint = $leafCert.Thumbprint
    $rootCert = $chain[-1].Certificate
    $rootIssuer = $rootCert.Subject
    $rootThumbprint = $rootCert.Thumbprint

    $sanExt = $leafCert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
    $sanList = if ($sanExt) { $sanExt.Format($false) -split ",\s*" } else { @() }
    $hostnameMatch = if (
        $leafSubject -match [regex]::Escape($TargetHost) -or
        ($sanList | Where-Object { $_ -match [regex]::Escape($TargetHost) })
    ) { "Match" } else { "Mismatch" }

    $issuerTrustStatus = if (
        $trustedMicrosoftRoots | Where-Object { $rootIssuer -like $_ }
    ) { "Microsoft" } else { "Non-Microsoft" }

 
    # Timestamp ESN via OID
    $tsExt = $leafCert.Extensions | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.2.1.27" }
    $timestampESN = if ($tsExt) {
        try {
            $rawBytes = $tsExt.RawData
            if ($rawBytes.Length -gt 0) {
                $decoded = [System.Text.Encoding]::UTF8.GetString($rawBytes)
                if ($decoded.Trim().Length -gt 0) {
                    $decoded
                }
                else {
                    "Present (non-printable)"
                }
            }
            else {
                "Present (empty)"
            }
        }
        catch {
            "Present (undecodable)"
        }
    }
    else {
        "-"
    }



    $chainDetails = foreach ($elem in $chain) {
        $c = $elem.Certificate
        $ekuExt = $c.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
        $ekuVal = if ($ekuExt) { $ekuExt.Format($false) } else { "" }
        [PSCustomObject]@{
            Subject      = $c.Subject
            Issuer       = $c.Issuer
            Thumbprint   = $c.Thumbprint
            NotBefore    = $c.NotBefore
            NotAfter     = $c.NotAfter
            SerialNumber = $c.SerialNumber
            EKU          = $ekuVal
        }
    }

    return @{
        LeafCertSubject    = $leafSubject
        LeafCertThumbprint = $leafThumbprint
        RootCertIssuer     = $rootIssuer
        RootCertThumbprint = $rootThumbprint
        HostnameMatch      = $hostnameMatch
        IssuerTrustStatus  = $issuerTrustStatus
        TimestampESN       = $timestampESN
        ChainDetails       = $chainDetails
    }
}



function Validate-CatalogIfESN {
    param(
        [string]$ESN,
        [string]$LeafThumb
    )

    if ([string]::IsNullOrWhiteSpace($ESN) -or $ESN -eq "-") {
        # Write-VerboseLog " Skipping catalog validation: ESN not present"
        return "Skipped"
    }

    try {
        $validationResult = Validate-CatalogChain -leafThumb $LeafThumb
        return $validationResult
    }
    catch {
        Write-VerboseLog " Catalog validation failed for $LeafThumb : $_"
        return "Error"
    }
}




function Reevaluate-TrustAnchor {
    param(
        [string]$LeafSubject,
        [string]$IssuerStatus,
        [bool]  $ChainComplete,
        [string]$RootSubject,
        [string]$GeoOrg
    )

    if (
        $LeafSubject -like "*microsoft.com*" -and
        $IssuerStatus -eq "Non-Microsoft" -and
        $ChainComplete -eq $true
    ) {
        if ($RootSubject -like "*Microsoft*" -or $GeoOrg -like "*Microsoft*") {
            Write-VerboseLog " Trust anchor reclassified as Microsoft"
            return "Microsoft"
        }
    }

    return $IssuerStatus
}

function Get-NIS2Classification {
    param(
        [string]$Hostname,
        [string]$ASN,
        [string]$Country,
        [string]$Issuer,
        [string]$RootIssuer,
        [string]$HostnameMatch,
        [string]$ChainComplete,
        [array]$ChainProvenance
    )


    $isEU = $Country -and ($euCountries -contains $Country)



    # Identity and API hostnames that should be treated as authoritative when PKI matches
    $identityApiList = @(
        "login.microsoftonline.com", "login.microsoftonline-p.com", "graph.windows.net",
        "login.windows.net", "login.live.com", "login.microsoft.com", "sts.windows.net"
    )

    # 1. PKI first rule for identity/API hostnames
    if ($HostnameMatch -eq "Match" -and $hasMicrosoftPKI -and $ChainComplete -eq "Yes" -and
        ($identityApiList -contains $Hostname -or $Hostname -match "graph|login|sts")) {
        return @{ Classification = "Authoritative"; Reason = "PKI match for identity/API" }
    }

    # 2. Quick authoritative root/issuer check
    if ($RootIssuer -and $RootIssuer -like "*Microsoft*" -and $Issuer -and $Issuer -like "*Microsoft*") {
        return @{ Classification = "Authoritative"; Reason = "Root and issuer indicate Microsoft" }
    }

    # 3. ASN corroboration for known authoritative ASNs
    $authoritativeASN = $false
    if ($ASN) {
        if ($ASN -match "8075|AS8075|Microsoft|Akamai|Fastly|Cloudflare") { $authoritativeASN = $true }
    }

    if (-not $authoritativeASN) {
        return @{ Classification = "Non-authoritative service path"; Reason = "ASN not authoritative" }
    }

    # 4. Cross-border check
    if (-not $isEU) {
        return @{ Classification = "Cross-border service-integrity anomaly"; Reason = "Edge outside EU" }
    }

    # 5. Hostname mismatch check
    if ($HostnameMatch -eq "Mismatch") {
        return @{ Classification = "Service integrity deviation"; Reason = "Hostname mismatch" }
    }

    # 6. Certificate chain issuer check
    if ($Issuer -and $RootIssuer -and ($Issuer -notlike "*Microsoft*" -and $RootIssuer -notlike "*Microsoft*")) {
        return @{ Classification = "Non-authoritative certificate chain"; Reason = "Non-Microsoft issuer/root" }
    }

    # 7. Default to authoritative if we reached here and ASN was authoritative
    return @{ Classification = "Authoritative"; Reason = "ASN corroboration and no deviations" }
}



function Build-ProbeResult {
    param(
        [string]$TargetHost, [string]$IP, [string]$IPVersion,
        [hashtable]$Geo, [string]$ASN, [hashtable]$Whois,
        [hashtable]$CertMeta, [hashtable]$TLSResult,
        [string]$CatalogValidation, [bool]$CatalogAttempted,
        [string]$IssuerTrustStatus, [int]$ProvenanceScore
    )
    $datadate = Get-Date -AsUTC
    if ($ChainProvenance) {
        foreach ($entry in $ChainProvenance) {
            if ($entry.Issuer -match "Microsoft|Azure" -or $entry.Subject -match "Microsoft|Azure") {
                $hasMicrosoftPKI = $true
                break
            }
        }
    } 
    return [PSCustomObject]@{
        Hostname                   = $TargetHost
        TIMEANDDATE                = $datadate
        IPAddress                  = $IP
        IPVersion                  = $IPVersion
        LeafCertSubject            = $CertMeta.LeafCertSubject
        LeafCertThumbprint         = $CertMeta.LeafCertThumbprint
        RootCertIssuer             = $CertMeta.RootCertIssuer
        RootCertThumbprint         = $CertMeta.RootCertThumbprint
        TLSVersion                 = $TLSResult.TLSVersion
        CipherSuite                = $TLSResult.CipherSuite
        HostnameMatch              = $CertMeta.HostnameMatch
        IssuerTrustStatus          = $IssuerTrustStatus
        ChainComplete              = if ($TLSResult.ChainBuilt) { "Yes" } else { "No" }
        TimestampESN               = $CertMeta.TimestampESN
        CatalogChainValidation     = $CatalogValidation
        CatalogValidationAttempted = $CatalogAttempted
        
        ChainProvenance            = $CertMeta.ChainDetails
        # Helper: detect Microsoft/Azure in chain
      
        GeoCity                    = $Geo.City
        GeoCountry                 = $Geo.Country
        GeoISP                     = $Geo.ISP
        GeoOrg                     = $Geo.Org
        ASN                        = if ($ASN -is [hashtable]) { "nouu $ASN.Org" } else { $ASN }
        $hasMicrosoftPKI           = $false
    
        WhoisOrgName               = $Whois.Name
        WhoisHandle                = $Whois.Handle
        WhoisAddress               = $Whois.Address
        WhoisContact               = $Whois.Contact
        ProvenanceScore            = $ProvenanceScore
        NIS2Classification         = Classify-NIS2 `
            -ASN $ASN.ASNOrg `
            -Country $Geo.Country `
            -Issuer $CertMeta.LeafCertSubject `
            -HostnameMatch $CertMeta.HostnameMatch `
            -RootIssuer $CertMeta.RootCertIssuer
        # Helper: detect Microsoft/Azure in chain
  
    } 
    if ($ipversion -eq "IPv6") {
        break
    }
   
}  
   

# -------------------- Config --------------------
$registryHostnames = @(
    "rdap.arin.net", "rdap.apnic.net", "rdap.afrinic.net",
    "rdap.lacnic.net", "rdap.ripe.net", "gateway2.lacnic.net.uy",
    "dblb-3.db.ripe.net"
)
# Helper: EU membership
$euCountries = @(
    "Austria", "Belgium", "Bulgaria", "Croatia", "Cyprus", "Czechia", "Denmark",
    "Estonia", "Finland", "France", "Germany", "Greece", "Hungary", "Ireland",
    "Italy", "Latvia", "Lithuania", "Luxembourg", "Malta", "Netherlands",
    "Poland", "Portugal", "Romania", "Slovakia", "Slovenia", "Spain", "Sweden"
)
$targetHostnames = @(
    # --- Update & Delivery Infrastructure ---
    # "fe2cr.update.microsoft.com" 
    #  "fe3cr.delivery.mp.microsoft.com",
    # "tsfe.trafficshaping.dsp.mp.microsoft.com" 
    # "download.windowsupdate.com",
    # "au.download.windowsupdate.com",
    # "redirectorupdates.microsoft.com",
    #    "delivery.mp.microsoft.com" 
    #     "edgeupdate.microsoft.com" 
    # "graphicsdelivery.windowsupdate.com",
    # "update.microsoft.com",
    # "download.microsoft.com",

    # # --- Delivery Optimization / CDN / ISP caches ---
    #  "tlu.dl.delivery.mp.microsoft.com" 
    #  "geo.delivery.mp.microsoft.com "
    # "ipv6.delivery.mp.microsoft.com",
    # "cdn.download.windowsupdate.com" 

    # # --- Identity & Login (Authoritative) ---
    #  "login.microsoftonline.com" 
    # "login.windows.net",
    # "login.live.com" 
    # "login.microsoft.com",
    # "account.microsoft.com",
    # "signup.live.com",
    #  "sts.windows.net" 
    # "secure.aadcdn.microsoftonline-p.com" 
    # # --- Identity & Conditional Access / Token endpoints ---
    #  "login.windowsazure.com",
    #  "login.microsoftonline-p.com",
    #  "login.microsoftonline-p.net", 

    # # --- Outlook, Exchange, Mail ---
    #  "outlook.office365.com",
    # "outlook.live.com",
    # "mail.protection.outlook.com",
    # "autodiscover.outlook.com",
    # "smtp.office365.com",
    # "smtp.office.com",

    # # --- OneDrive, SharePoint, Office files ---
    #  "onedrive.live.com",
    # "onedrive.office.com",
    # "sharepoint.com",
    # "tenant.sharepoint.com",
    # "officecdn.microsoft.com",
    # "officeclient.microsoft.com",

    # # --- Office, Teams, Collaboration ---
    # "office.com"
    # "www.office.com",
    # "portal.office.com",
    # "teams.microsoft.com",
    # "teams.live.com",

    # # --- Microsoft Graph and APIs ---
    #  "graph.microsoft.com" 
    # "graph.windows.net",
    # "management.azure.com",
    # "api.office.com",

    # # --- Azure control plane and telemetry (critical for cloud services) ---
    # "login.azure.com",
    "portal.azure.com" 
    # "management.azure.com",
    # "blob.core.windows.net" 
    # "vault.azure.net",

    # # --- Redirectors and short links used in telemetry and support ---
    # "go.microsoft.com",
    # "msftconnecttest.com",

    # --- Time and CRL/OCSP (certificate validation) ---
    #  "time.windows.com" 
    # "crl.microsoft.com",
    #  "ocsp.digicert.com"
)

$scoreThresholds = @{
    ManualReview = 1    # ProvenanceScore ≤ 1
    AutoTrust    = 3    # ProvenanceScore ≥ 3
}
$cdnSuppress = @{
   ## COULD SUPPRESS MICROSOFT PARTNER CDNs:
   
   # Thumbprints = @("CE8232BDB6C1422965FC6BB6915AB2135E7A3EF6", "6109B882967FE122E0AB59736BFFA707D684878A"  , "6109B882967FE122E0AB59736BFFA707D684878A")
   # Issuers     = @("*Akamai*", "*Fastly*", "*Certainly*")
}

function Register-SuppressionEntry {
    param($thumb, $issuerPattern)
    $cdnSuppress.Thumbprints += $thumb
    $cdnSuppress.Issuers += $issuerPattern
}

function Should-Suppress {
    param($thumb, $issuer)
    return ($cdnSuppress.Thumbprints -contains $thumb) -or
    ($cdnSuppress.Issuers     | Where-Object { $issuer -like $_ })
}

function Classify-Result {
    param($result)
    if (Should-Suppress $result.Thumbprint $result.RootCertIssuer) {
        $result.Action = 'Suppress'
    }
    elseif ($result.ProvenanceScore -le $scoreThresholds.ManualReview) {
        $result.Action = 'Review'
    }
    else {
        $result.Action = 'Trust'
    }
    return $result
}
function Invoke-CatalogValidation {
    param([string]$leafThumb)
    # real chain validation logic goes here
    return "Success"  # or "Fail"
}


function Write-VerboseLog {
    param([string]$msg)
    if ($verboseOutput) { Write-Host $msg }
}

# MAIN LOOP
foreach ($targetHost in $targetHostnames) {
    Write-VerboseLog "`n  Probing $targetHost..."

    $resolvedIPs = Resolve-TargetIPs -Hostname $targetHost
    foreach ($ip in $resolvedIPs) {
        Write-VerboseLog "   $ip"

        $ipVersion = if ($ip -match ":") { "IPv6" } else { "IPv4" }
        $geo = Get-GeoInfo -ip $ip
        $asn = Get-ASNInfo -ip $ip
        $whois = Get-WhoisInfo -ip $ip
     
        $tlsResult = Perform-TLSProbe -IP $ip -TargetHost $targetHost -IPVersion $ipVersion
        $certMeta = Extract-CertMetadata -TLSResult $tlsResult -TargetHost $targetHost

        $catalogValidation = Validate-CatalogIfESN -ESN $certMeta.TimestampESN -LeafThumb $certMeta.LeafThumbprint
        $catalogAttempted = ($certMeta.TimestampESN -ne "-" -and $null -ne $certMeta.TimestampESN)

        $issuerTrustStatus = Reevaluate-TrustAnchor -LeafSubject $certMeta.LeafCertSubject `
            -IssuerStatus $certMeta.IssuerTrustStatus `
            -ChainComplete $tlsResult.ChainBuilt `
            -RootSubject $certMeta.RootCertIssuer `
            -GeoOrg $geo.Org

        $provenanceScore = Score-Provenance `
            -issuer $certMeta.RootCertIssuer `
            -subject $certMeta.LeafCertSubject `
            -targetHost $targetHost `
            -chainComplete $tlsResult.ChainBuilt `
            -isRegistry ($registryHostnames -contains $targetHost)
 
        $probeResults += Build-ProbeResult -TargetHost $targetHost -IP $ip -IPVersion $ipVersion `
            -Geo $geo -ASN $asn -Whois $whois `
            -CertMeta $certMeta -TLSResult $tlsResult `
            -CatalogValidation $catalogValidation `
            -CatalogAttempted $catalogAttempted `
            -IssuerTrustStatus $issuerTrustStatus `
            -ProvenanceScore $provenanceScore
    }
}

# -------------------- Export --------------------
$probeResults | Export-Csv -Path $exportCsv -NoTypeInformation -Encoding UTF8
$probeResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $exportJson -Encoding UTF8
