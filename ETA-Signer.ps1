# ETA-Signer.ps1 v2 - local agent: signs with the USB token AND talks to the ETA API (no cloud needed)
# Run:   powershell -NoProfile -ExecutionPolicy Bypass -File ETA-Signer.ps1 -AllowedOrigin "https://your-app-address"
# Setup: powershell -NoProfile -ExecutionPolicy Bypass -File ETA-Signer.ps1 -SetCredentials pre [-Rin 123456789] [-Intermediary]
param([string]$AllowedOrigin = '', [int]$Port = 5211, [string]$SetCredentials = '', [string]$Rin = '', [switch]$Intermediary)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security
$Hosts = @{ pre = @{ id = 'https://id.preprod.eta.gov.eg'; api = 'https://api.preprod.invoicing.eta.gov.eg' }; prod = @{ id = 'https://id.eta.gov.eg'; api = 'https://api.invoicing.eta.gov.eg' } }
$CredDir = Join-Path $env:APPDATA 'ETA-Signer'

# ---------- one-time credential setup (secret is typed here, never in the browser) ----------
if ($SetCredentials) {
  if (@('pre','prod') -notcontains $SetCredentials) { Write-Host "Environment must be 'pre' or 'prod'"; exit 1 }
  $cid = Read-Host 'ETA Client ID'
  $sec = Read-Host 'ETA Client Secret' -AsSecureString
  New-Item -ItemType Directory -Force -Path $CredDir | Out-Null
  $name = if ($Rin) { "cred-$SetCredentials-$Rin.json" } else { "cred-$SetCredentials-default.json" }
  @{ clientId = $cid; secret = (ConvertFrom-SecureString $sec); intermediary = [bool]$Intermediary } | ConvertTo-Json | Set-Content -Path (Join-Path $CredDir $name) -Encoding UTF8
  Write-Host "Saved (encrypted for this Windows user): $name"; exit 0
}

if (-not $AllowedOrigin) { $AllowedOrigin = Read-Host 'Enter the web app address (example https://your-app.web.app)' }
$AllowedOrigin = $AllowedOrigin.Trim().TrimEnd('/')

function Der([byte]$tag, [byte[]]$c) {
  $m = New-Object System.Collections.Generic.List[byte]
  $m.Add($tag); $n = $c.Length
  if ($n -lt 128) { $m.Add([byte]$n) }
  else { $lb = New-Object System.Collections.Generic.List[byte]; while ($n -gt 0) { $lb.Insert(0, [byte]($n -band 255)); $n = $n -shr 8 }; $m.Add([byte](128 + $lb.Count)); $m.AddRange($lb) }
  $m.AddRange($c); return ,$m.ToArray()
}
function Cat { $m = New-Object System.Collections.Generic.List[byte]; foreach ($x in $args) { $m.AddRange([byte[]]$x) }; return ,$m.ToArray() }
function Get-Certs { @(Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) }) }
function Get-SigningCertV2([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
  $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
  $certHash = Der 0x04 $hash
  $genNames = Der 0x30 (Der 0xA4 $cert.IssuerName.RawData)
  $sn = $cert.GetSerialNumber(); [array]::Reverse($sn)
  if ($sn[0] -ge 128) { $sn = [byte[]](@(0) + $sn) }
  $issuerSerial = Der 0x30 (Cat $genNames (Der 0x02 $sn))
  return ,(Der 0x30 (Der 0x30 (Der 0x30 (Cat $certHash $issuerSerial))))
}
function Sign-Data([byte[]]$data, $cert) {
  $ci = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList @(,$data)
  $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $ci, $false
  $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList $cert
  $signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid -ArgumentList '2.16.840.1.101.3.4.2.1'
  $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
  [void]$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.Pkcs.Pkcs9SigningTime))
  $oid = New-Object System.Security.Cryptography.Oid -ArgumentList '1.2.840.113549.1.9.16.2.47'
  [void]$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.AsnEncodedData -ArgumentList $oid, (Get-SigningCertV2 $cert)))
  $cms.ComputeSignature($signer, $false)
  return [Convert]::ToBase64String($cms.Encode())
}

# ---------- ETA API ----------
$script:Tok = @{}
function Get-Cred($e, $rin) {
  foreach ($n in @("cred-$e-$rin.json", "cred-$e-default.json")) {
    $p = Join-Path $CredDir $n
    if (Test-Path $p) {
      $j = Get-Content $p -Raw | ConvertFrom-Json
      $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString $j.secret)))
      return @{ clientId = $j.clientId; secret = $plain; inter = [bool]$j.intermediary }
    }
  }
  return $null
}
function Http([string]$method, [string]$uri, [hashtable]$headers, $body, [string]$ctype) {
  try {
    $p = @{ Method = $method; Uri = $uri; Headers = $headers; UseBasicParsing = $true; TimeoutSec = 60 }
    if ($null -ne $body) { $p.Body = [Text.Encoding]::UTF8.GetBytes([string]$body); $p.ContentType = $ctype }
    $r = Invoke-WebRequest @p
    return @{ code = [int]$r.StatusCode; body = [string]$r.Content }
  } catch {
    $resp = $_.Exception.Response
    if ($resp) { $sr = New-Object IO.StreamReader($resp.GetResponseStream()); return @{ code = [int]$resp.StatusCode; body = $sr.ReadToEnd() } }
    return @{ code = 0; body = $_.Exception.Message }
  }
}
function Get-Token($e, $rin) {
  $k = "$e|$rin"; $c = $script:Tok[$k]
  if ($c -and $c.exp -gt (Get-Date).AddSeconds(60)) { return $c.t }
  $cr = Get-Cred $e $rin
  if (-not $cr) { throw "No credentials saved for '$e'. Run set-credentials.bat first." }
  $h = @{}; if ($cr.inter) { $h['onbehalfof'] = $rin }
  $form = 'grant_type=client_credentials&scope=InvoicingAPI&client_id=' + [uri]::EscapeDataString($cr.clientId) + '&client_secret=' + [uri]::EscapeDataString($cr.secret)
  $r = Http 'POST' ($Hosts[$e].id + '/connect/token') $h $form 'application/x-www-form-urlencoded'
  if ($r.code -ne 200) { throw ("ETA login failed (HTTP " + $r.code + "): " + $r.body) }
  $j = $r.body | ConvertFrom-Json
  $script:Tok[$k] = @{ t = $j.access_token; exp = (Get-Date).AddSeconds([int]$j.expires_in) }
  return $j.access_token
}
function Eta-Call($e, $rin, [string]$method, [string]$path, $body) {
  for ($try = 0; $try -lt 2; $try++) {
    $tok = Get-Token $e $rin
    $r = Http $method ($Hosts[$e].api + $path) @{ Authorization = "Bearer $tok"; 'Accept-Language' = 'ar' } $body 'application/json'
    if ($r.code -ne 401) { return $r }
    $script:Tok.Remove("$e|$rin")
  }
  return $r
}
function Send($res, [int]$code, $obj) {
  $b = [Text.Encoding]::UTF8.GetBytes(($obj | ConvertTo-Json -Depth 5 -Compress))
  $res.StatusCode = $code; $res.ContentType = 'application/json; charset=utf-8'
  $res.ContentLength64 = $b.Length; $res.OutputStream.Write($b, 0, $b.Length); $res.OutputStream.Close()
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
Write-Host "ETA agent running on http://localhost:$Port  (allowed origin: $AllowedOrigin)"
Write-Host 'Keep this window open. Press Ctrl+C to stop.'
while ($listener.IsListening) {
  $ctx = $listener.GetContext(); $req = $ctx.Request; $res = $ctx.Response
  try {
    $origin = $req.Headers['Origin']
    if ($origin) {
      if ($origin.TrimEnd('/') -ne $AllowedOrigin) { Send $res 403 @{ error = 'origin not allowed' }; continue }
      $res.AddHeader('Access-Control-Allow-Origin', $origin); $res.AddHeader('Access-Control-Allow-Headers', 'Content-Type')
      $res.AddHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS'); $res.AddHeader('Access-Control-Allow-Private-Network', 'true'); $res.AddHeader('Vary', 'Origin')
    }
    if ($req.HttpMethod -eq 'OPTIONS') { $res.StatusCode = 204; $res.OutputStream.Close(); continue }
    $path = $req.Url.AbsolutePath
    if ($path -eq '/ping' -and $req.HttpMethod -eq 'GET') {
      $list = @(Get-Certs | ForEach-Object { @{ subject = $_.GetNameInfo('SimpleName', $false); issuer = $_.GetNameInfo('SimpleName', $true); thumbprint = $_.Thumbprint; notAfter = $_.NotAfter.ToString('yyyy-MM-dd') } })
      Send $res 200 @{ ok = $true; version = 2; certs = $list }; continue
    }
    if ($req.HttpMethod -ne 'POST') { Send $res 404 @{ error = 'not found' }; continue }
    $body = (New-Object System.IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)).ReadToEnd() | ConvertFrom-Json
    if ($path -eq '/sign') {
      $certs = Get-Certs
      $cert = if ($body.thumbprint) { $certs | Where-Object { $_.Thumbprint -eq $body.thumbprint } | Select-Object -First 1 } elseif ($certs.Count -eq 1) { $certs[0] } else { $null }
      if (-not $cert) { Send $res 400 @{ error = 'certificate not found - insert the token or pick a thumbprint' }; continue }
      $sig = Sign-Data ([Text.Encoding]::UTF8.GetBytes([string]$body.canonical)) $cert
      Write-Host ("{0}  signed" -f (Get-Date -Format 'HH:mm:ss')); Send $res 200 @{ signature = $sig }; continue
    }
    if ($path -like '/eta/*') {
      $e = [string]$body.env; $rin = [string]$body.rin
      if (@('pre','prod') -notcontains $e) { Send $res 400 @{ error = 'bad env' }; continue }
      if ($rin -notmatch '^\d{9}$') { Send $res 400 @{ error = 'bad tax number' }; continue }
      try { [void](Get-Token $e $rin) } catch { Send $res 400 @{ error = $_.Exception.Message }; continue }
      if ($path -eq '/eta/ping') { Send $res 200 @{ ok = $true }; continue }
      if ($path -eq '/eta/submit') { $r = Eta-Call $e $rin 'POST' '/api/v1.0/documentsubmissions/' ([string]$body.body) }
      elseif ($path -eq '/eta/document' -and ([string]$body.uuid) -match '^[A-Za-z0-9-]{10,64}$') { $r = Eta-Call $e $rin 'GET' ('/api/v1.0/documents/' + $body.uuid + '/details') $null }
      elseif ($path -eq '/eta/submission' -and ([string]$body.id) -match '^[A-Za-z0-9-]{10,64}$') { $r = Eta-Call $e $rin 'GET' ('/api/v1.0/documentsubmissions/' + $body.id) $null }
      else { Send $res 404 @{ error = 'not found' }; continue }
      Write-Host ("{0}  {1} -> HTTP {2}" -f (Get-Date -Format 'HH:mm:ss'), $path, $r.code)
      Send $res 200 @{ code = $r.code; body = $r.body }; continue
    }
    Send $res 404 @{ error = 'not found' }
  } catch {
    try { Send $res 500 @{ error = $_.Exception.Message } } catch {}
    Write-Host ("ERROR: " + $_.Exception.Message)
  }
}
