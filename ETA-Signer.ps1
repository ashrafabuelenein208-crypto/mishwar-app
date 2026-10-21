# ETA-Signer.ps1 - local CAdES-BES signer for the ETA e-invoice (uses the Windows certificate store / USB token)
# Run:  powershell -NoProfile -ExecutionPolicy Bypass -File ETA-Signer.ps1 -AllowedOrigin "https://your-app-address"
param([string]$AllowedOrigin = '', [int]$Port = 5211)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
if (-not $AllowedOrigin) { $AllowedOrigin = Read-Host 'Enter the web app address (example https://your-app.web.app)' }
$AllowedOrigin = $AllowedOrigin.Trim().TrimEnd('/')

function Der([byte]$tag, [byte[]]$c) {
  $m = New-Object System.Collections.Generic.List[byte]
  $m.Add($tag); $n = $c.Length
  if ($n -lt 128) { $m.Add([byte]$n) }
  else {
    $lb = New-Object System.Collections.Generic.List[byte]
    while ($n -gt 0) { $lb.Insert(0, [byte]($n -band 255)); $n = $n -shr 8 }
    $m.Add([byte](128 + $lb.Count)); $m.AddRange($lb)
  }
  $m.AddRange($c)
  return ,$m.ToArray()
}
function Cat {
  $m = New-Object System.Collections.Generic.List[byte]
  foreach ($x in $args) { $m.AddRange([byte[]]$x) }
  return ,$m.ToArray()
}
function Get-Certs {
  @(Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) })
}
function Get-SigningCertV2([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
  # ESS signing-certificate-v2 (RFC 5035), SHA-256 (default algorithm, so omitted)
  $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
  $certHash = Der 0x04 $hash
  $dirName = Der 0xA4 $cert.IssuerName.RawData
  $genNames = Der 0x30 $dirName
  $sn = $cert.GetSerialNumber(); [array]::Reverse($sn)
  if ($sn[0] -ge 128) { $sn = [byte[]](@(0) + $sn) }
  $serial = Der 0x02 $sn
  $issuerSerial = Der 0x30 (Cat $genNames $serial)
  $essId = Der 0x30 (Cat $certHash $issuerSerial)
  $certs = Der 0x30 $essId
  return ,(Der 0x30 $certs)
}
function Sign-Data([byte[]]$data, $cert) {
  $ci = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,$data)
  $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $ci, $false
  $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList $cert
  $signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid -ArgumentList '2.16.840.1.101.3.4.2.1'
  $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
  [void]$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.Pkcs.Pkcs9SigningTime))
  $oid = New-Object System.Security.Cryptography.Oid -ArgumentList '1.2.840.113549.1.9.16.2.47'
  $scv2 = Get-SigningCertV2 $cert
  [void]$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.AsnEncodedData -ArgumentList $oid, $scv2))
  $cms.ComputeSignature($signer, $false)   # $false = allow the token PIN prompt
  return [Convert]::ToBase64String($cms.Encode())
}
function Send($res, [int]$code, $obj) {
  $json = $obj | ConvertTo-Json -Depth 5 -Compress
  $b = [Text.Encoding]::UTF8.GetBytes($json)
  $res.StatusCode = $code; $res.ContentType = 'application/json; charset=utf-8'
  $res.ContentLength64 = $b.Length; $res.OutputStream.Write($b, 0, $b.Length); $res.OutputStream.Close()
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
Write-Host "ETA signer running on http://localhost:$Port  (allowed origin: $AllowedOrigin)"
Write-Host 'Keep this window open. Press Ctrl+C to stop.'
while ($listener.IsListening) {
  $ctx = $listener.GetContext(); $req = $ctx.Request; $res = $ctx.Response
  try {
    $origin = $req.Headers['Origin']
    if ($origin) {
      if ($origin.TrimEnd('/') -ne $AllowedOrigin) { Send $res 403 @{ error = 'origin not allowed' }; continue }
      $res.AddHeader('Access-Control-Allow-Origin', $origin)
      $res.AddHeader('Access-Control-Allow-Headers', 'Content-Type')
      $res.AddHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
      $res.AddHeader('Access-Control-Allow-Private-Network', 'true')
      $res.AddHeader('Vary', 'Origin')
    }
    if ($req.HttpMethod -eq 'OPTIONS') { $res.StatusCode = 204; $res.OutputStream.Close(); continue }
    $path = $req.Url.AbsolutePath
    if ($path -eq '/ping' -and $req.HttpMethod -eq 'GET') {
      $list = @(Get-Certs | ForEach-Object { @{ subject = $_.GetNameInfo('SimpleName', $false); issuer = $_.GetNameInfo('SimpleName', $true); thumbprint = $_.Thumbprint; notAfter = $_.NotAfter.ToString('yyyy-MM-dd') } })
      Send $res 200 @{ ok = $true; certs = $list }; continue
    }
    if ($path -eq '/sign' -and $req.HttpMethod -eq 'POST') {
      $body = (New-Object System.IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)).ReadToEnd() | ConvertFrom-Json
      $certs = Get-Certs
      $cert = if ($body.thumbprint) { $certs | Where-Object { $_.Thumbprint -eq $body.thumbprint } | Select-Object -First 1 } elseif ($certs.Count -eq 1) { $certs[0] } else { $null }
      if (-not $cert) { Send $res 400 @{ error = 'certificate not found - insert the token or pick a thumbprint' }; continue }
      $sig = Sign-Data ([Text.Encoding]::UTF8.GetBytes([string]$body.canonical)) $cert
      Write-Host ("{0}  signed ({1} chars)" -f (Get-Date -Format 'HH:mm:ss'), ([string]$body.canonical).Length)
      Send $res 200 @{ signature = $sig }; continue
    }
    Send $res 404 @{ error = 'not found' }
  } catch {
    try { Send $res 500 @{ error = $_.Exception.Message } } catch {}
    Write-Host ("ERROR: " + $_.Exception.Message)
  }
}
