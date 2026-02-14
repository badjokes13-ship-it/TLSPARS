function Classify-NIS2 {
    param(
        [string]$ASN,
        [string]$Country,
        [string]$Issuer,
        [string]$HostnameMatch,
        [string]$RootIssuer
    )

    $isEU = $Country -in @(
        "Austria","Belgium","Bulgaria","Croatia","Cyprus","Czechia","Denmark",
        "Estonia","Finland","France","Germany","Greece","Hungary","Ireland",
        "Italy","Latvia","Lithuania","Luxembourg","Malta","Netherlands",
        "Poland","Portugal","Romania","Slovakia","Slovenia","Spain","Sweden"
    )

    $authoritativeASN = $ASN -match "Microsoft|Akamai|Fastly"

    if (-not $authoritativeASN) {
        return "Non-authoritative service path"
    }

    if (-not $isEU) {
        return "Cross-border service-integrity anomaly"
    }

    if ($HostnameMatch -eq "Mismatch") {
        return "Service integrity deviation"
    }

    if ($Issuer -notlike "*Microsoft*" -and $RootIssuer -notlike "*Microsoft*") {
        return "Non-authoritative certificate chain"
    }

    return "Authoritative"
}
