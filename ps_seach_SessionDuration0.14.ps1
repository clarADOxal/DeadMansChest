#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

# ==========================================================
# EVTX User Sessions Timeline (Logon/Logoff Analysis)
#
# Input : $Path
# Output:
#   .\out\YYMMDD-UserSessions.csv
#   .\out\YYMMDD-UserSessions.html
# Version  : 0.14
# ==========================================================
cls

write-host -fore red "██████╗░███████╗░█████╗░██████╗░  ███╗░░░███╗░█████╗░███╗░░██╗"
write-host -fore red "██╔══██╗██╔════╝██╔══██╗██╔══██╗  ████╗░████║██╔══██╗████╗░██║"
write-host -fore red "██║░░██║█████╗░░███████║██║░░██║  ██╔████╔██║███████║██╔██╗██║"
write-host -fore red "██║░░██║██╔══╝░░██╔══██║██║░░██║  ██║╚██╔╝██║██╔══██║██║╚████║"
write-host -fore red "██████╔╝███████╗██║░░██║██████╔╝  ██║░╚═╝░██║██║░░██║██║░╚███║"
write-host -fore red "╚═════╝░╚══════╝╚═╝░░╚═╝╚═════╝░  ╚═╝░░░░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝"
write-host "E-Discovery : Extract User Sessions (Logon/Logoff) from EVTX into HTML+CSV"
write-host ""

# ----------------------------------------------------------
# Gestion des répertoires
# ----------------------------------------------------------
$OutputDir = ".\out"
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

if (-not (Test-Path $Path)) {
    write-host -fore red "$Path n'existe pas, veuillez vérifier le chemin."
    sleep 2
    exit
}

# Vérification et localisation des EVTX (Sécurité)
$EvtxFiles = Get-ChildItem -Path $Path -File | Where-Object { $_.Name -match '^Security.*\.evtx$' }
if (-not $EvtxFiles -or $EvtxFiles.Count -lt 1) {
    write-host -fore red "Aucun fichier Security.evtx trouvé dans $Path. Recherche dans Windows\System32\winevt\Logs..."
    $Path = Join-Path -Path $Path -ChildPath "Windows\System32\winevt\Logs"
    
    if (-not (Test-Path $Path)) {
        write-host -fore red "$Path introuvable, arrêt du script."
        sleep 2
        exit
    }
    
    $EvtxFiles = Get-ChildItem -Path $Path -File | Where-Object { $_.Name -match '^Security.*\.evtx$' }
    if (-not $EvtxFiles) {
        write-host -fore red "Aucun journal de sécurité (Security.evtx) trouvé, arrêt."
        sleep 2
        exit
    }
}

$DateStamp = Get-Date -Format "yyMMdd-HHmmss"
$CsvFile = Join-Path $OutputDir "$DateStamp-UserSessions.csv"
$HtmlFile = Join-Path $OutputDir "$DateStamp-UserSessions.html"

# ----------------------------------------------------------
# Timeline optionnelle
# ----------------------------------------------------------
$StartDate = $null
$EndDate = $null

$UseTimeline = Read-Host "Limiter la période (UTC) ? (O/N)"

if ($UseTimeline -match '^[OoYy]') {
    try {
        $StartDateInput = Read-Host "Date de début (YYYY-MM-DD HH:mm:ss)"
        $EndDateInput   = Read-Host "Date de fin   (YYYY-MM-DD HH:mm:ss) [Entrée = maintenant]"

        $StartDate = [datetime]::ParseExact($StartDateInput, 'yyyy-MM-dd HH:mm:ss', $null)

        if ([string]::IsNullOrWhiteSpace($EndDateInput)) {
            $EndDate = Get-Date
        } else {
            $EndDate = [datetime]::ParseExact($EndDateInput, 'yyyy-MM-dd HH:mm:ss', $null)
        }

        Write-Host "Période limitée du $($StartDate.ToString('yyyy-MM-dd HH:mm:ss')) au $($EndDate.ToString('yyyy-MM-dd HH:mm:ss')) (UTC)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Format de date invalide. Analyse complète sans filtre."
        $StartDate = $null
        $EndDate   = $null
    }
}

function Test-DateRange {
    param([datetime]$EventDate)
    if ($null -eq $StartDate -or $null -eq $EndDate) { return $true }
    $UtcDate = $EventDate.ToUniversalTime()
    return ($UtcDate -ge $StartDate -and $UtcDate -le $EndDate)
}

function Get-ReadableDuration {
    param($ts)
    if (-not $ts -or $ts.TotalSeconds -lt 0) { return "En cours / Inconnue" }
    if ($ts.TotalDays -ge 1)    { return "{0:N1} j" -f $ts.TotalDays }
    if ($ts.TotalHours -ge 1)   { return "{0:N1} h" -f $ts.TotalHours }
    if ($ts.TotalMinutes -ge 1) { return "{0:N1} m" -f $ts.TotalMinutes }
    return "$([math]::Round($ts.TotalSeconds)) s"
}

# ----------------------------------------------------------
# Analyse des EVTX (IDs 4624 et 4634)
# ----------------------------------------------------------
$sessions = [ordered]@{}
$XPath = "*[System[(EventID=4624 or EventID=4634)]]"

foreach ($Evtx in $EvtxFiles) {
    Write-Host "Analyse en cours : $($Evtx.Name)"

    try {
        Get-WinEvent -Path $Evtx.FullName -FilterXPath $XPath -ErrorAction Stop | ForEach-Object {
            $Evt = $_

            if (-not (Test-DateRange $Evt.TimeCreated)) { return }

            try {
                $xml = [xml]$Evt.ToXml()
                $data = $xml.Event.EventData.Data

                $logonId = ($data | Where-Object Name -eq "TargetLogonId").'#text'
                if (-not $logonId) { $logonId = ($data | Where-Object Name -eq "LogonId").'#text' }
                
                $user = ($data | Where-Object Name -eq "TargetUserName").'#text'
                $logonType = ($data | Where-Object Name -eq "LogonType").'#text'
                $workstation = ($data | Where-Object Name -eq "WorkstationName").'#text'

                if (-not $logonId) { return }

                # Filtrage strict des comptes système, DWM, UMFD et comptes machines ($)
                if (
                    [string]::IsNullOrWhiteSpace($user) -or
                    $user -match '\$$' -or
                    $user -match '^DWM-' -or
                    $user -match '^UMFD-' -or
                    $user -in @(
                        'SYSTEM',
                        'LOCAL SERVICE',
                        'NETWORK SERVICE',
                        'ANONYMOUS LOGON',
                        'WINDOWSTRANSPORT$'
                    )
                ) {
                    return
                }

                if ($Evt.Id -eq 4624) {
                    # Conserver uniquement les types pertinents (ex: Interactif [2], RemoteInteractive [10])
                    if ($logonType -notin @("2", "10")) { return }

                    if (-not $sessions.Contains($logonId)) {
                        $sessions[$logonId] = [PSCustomObject]@{
                            LogonId   = $logonId
                            User      = $user
                            LogonType = $logonType
                            Host      = if ($workstation -and $workstation -ne "-") { $workstation } else { "N/A" }
                            Start     = $Evt.TimeCreated.ToUniversalTime()
                            End       = $null
                        }
                    }
                }
                elseif ($Evt.Id -eq 4634) {
                    if ($sessions.Contains($logonId) -and -not $sessions[$logonId].End) {
                        $sessions[$logonId].End = $Evt.TimeCreated.ToUniversalTime()
                    }
                }
            }
            catch {}
        }
    }
    catch {
        Write-Warning "Impossible de lire le fichier : $($Evtx.Name)"
    }
}

$sessionList = $sessions.Values | Sort-Object Start

# ----------------------------------------------------------
# Export CSV
# ----------------------------------------------------------
$resultsForCsv = foreach ($s in $sessionList) {
    $dur = if ($s.End) { ($s.End - $s.Start) } else { $null }
    [PSCustomObject]@{
        LogonId   = $s.LogonId
        User      = $s.User
        LogonType = $s.LogonType
        Host      = $s.Host
        Start     = $s.Start.ToString("yyyy-MM-dd HH:mm:ss")
        End       = if ($s.End) { $s.End.ToString("yyyy-MM-dd HH:mm:ss") } else { "OPEN" }
        Duree     = Get-ReadableDuration $dur
    }
}

$resultsForCsv | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8

# ----------------------------------------------------------
# Statistiques pour le HTML
# ----------------------------------------------------------
$TotalSessions = $sessionList.Count
$OpenSessions = ($sessionList | Where-Object { $_.End -eq $null }).Count

$Rows = foreach ($s in $sessionList) {
    $dur = if ($s.End) { ($s.End - $s.Start) } else { $null }
    $durStr = Get-ReadableDuration $dur
    $endStr = if ($s.End) { $s.End.ToString("yyyy-MM-dd HH:mm:ss") } else { "En cours" }
    $class = if ($s.End) { "closed-session" } else { "open-session" }

@"
<tr class='$class'>
<td>$($s.Start.ToString("yyyy-MM-dd HH:mm:ss")) UTC</td>
<td>$endStr UTC</td>
<td>$durStr</td>
<td>$($s.User)</td>
<td>$($s.LogonType)</td>
<td>$($s.Host)</td>
<td>$($s.LogonId)</td>
</tr>
"@
}

# ----------------------------------------------------------
# Génération du Rapport HTML Interactif
# ----------------------------------------------------------
$Html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Rapport des Sessions Utilisateurs</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f9f9f9; color: #333; }
h1, h2 { color: #222; }
table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
th, td { border: 1px solid #ddd; padding: 8px 12px; font-size: 13px; text-align: left; }
th { background: #333; color: white; }
.open-session { background: #fff0cc; }
.closed-session { background: #d9fdd3; }
.summary-box { background: #fff; padding: 15px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }
</style>
</head>
<body>

<h1>Rapport des Sessions Utilisateurs (EVTX)</h1>

<div class="summary-box">
    <h2>Résumé</h2>
    <ul>
        <li><strong>Sessions utilisateur totales analysées :</strong> $TotalSessions</li>
        <li><strong>Sessions encore ouvertes :</strong> $OpenSessions</li>
    </ul>
</div>

<h2>Timeline des Sessions</h2>
<table>
<thead>
<tr>
<th>Début (UTC)</th>
<th>Fin (UTC)</th>
<th>Durée</th>
<th>Utilisateur</th>
<th>Type Logon</th>
<th>Poste / Host</th>
<th>Logon ID</th>
</tr>
</thead>
<tbody>
$($Rows -join "`n")
</tbody>
</table>

</body>
</html>
"@

$Html | Out-File -FilePath $HtmlFile -Encoding UTF8

# ----------------------------------------------------------
# Fin du script
# ----------------------------------------------------------
Write-Host "`nAnalyse terminée avec succès !" -ForegroundColor Green
Write-Host "CSV  : $CsvFile" -ForegroundColor Cyan
Write-Host "HTML : $HtmlFile" -ForegroundColor Cyan

Start-Process $HtmlFile