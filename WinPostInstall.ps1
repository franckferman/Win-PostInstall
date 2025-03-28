# ===============================
# WinPostInstall
# ===============================

<#
.SYNOPSIS
WinPostInstall is a post-installation automation script for configuring, customizing, and hardening Windows systems.

.DESCRIPTION
WinPostInstall is a modular PowerShell script designed to automate the setup of freshly installed Windows machines. 
It handles everything from system configuration, privacy tweaks, app installations (via WinGet & Microsoft Store), Windows hardening, developer tools, to theming and bloatware removal.

This script is ideal for power users, developers, cybersecurity professionals, and system administrators who want a fully customized and optimized Windows environment without manual effort.

WinPostInstall is interactive, colorful, and clean — built with modularity and idempotence in mind. 
The user experience is enhanced with timestamps, clear status messages, and smart checks to avoid redundant actions.

.INPUTS
None. All configurations are handled internally or interactively where needed.

.OUTPUTS
Console output with styled messages (success, warning, error) and optional logs depending on configuration.

.REQUIREMENTS
- PowerShell 5.1 or later 
- Administrator privileges 
- Internet access for Winget and Store apps

.LICENSE
Distributed under the GNU Affero General Public License v3.0. See [LICENSE](https://github.com/franckferman/franckferman/blob/stable/LICENSE) for full license details.

.CREDITS
[HardeningKitty](https://github.com/scipag/HardeningKitty)
[Win11Debloat](https://github.com/Raphire/Win11Debloat)

.EXAMPLE
PS > Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process; .\WinPostInstall.ps1

.NOTES
Author  : Franck FERMAN
Version : 1.0.0
License : GNU AGPLv3
GitHub  : https://github.com/franckferman/

.LINK
https://github.com/franckferman/WinPostInstall
#>


param(
  [switch]$Help,
  [switch]$AfterRestart
)


function Get-Banner {
  param(
    [Parameter(Mandatory = $false)]
    [string]$BannerType
  )

$Banners = @{
  "Window_PS_Terminal" = @"
 _______________________________________________________________________
|[>] Win-Post-Install                    [-]|[]|[x]"|
|"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""|"|
|PS C:\WINDOWS\system32> Set-Location -Path C:\Users\$env:USERNAME       | |
|PS C:\Users\$env:USERNAME> .\WinPostInstall.ps1                | |
|                                   |_|
|_____________________________________________________________________|/|
"@

	"Window_PS_Terminal_Old_Computer" = @"
 .---------.
 |.-------.|
 ||PS C:\>||
 ||    ||
 |"-------'|
.-^---------^-.
| ---~[WPI  |
| franck]---~|
"-------------'
"@

	"Teddy_Screen" = @"
           ,---.      ,---.
          / /"'.\.--"""--./,'"\ \
          \ \  _    _  / /
           './ / __  __ \ \,'
           /  /_O)_(_O\  \
           | .-' ___ '-. |
          .--|    \_/    |--.
         ,'  \  \  |  /  /  '.
        /    '. '--^--' ,'    \
       .-"""""-.  '--.___.--'   .-"""""-.
.-----------/     \------------------/     \--------------.
| .---------\     /----------------- \     /------------. |
| |     '-'--'--'          '--'--'-'       | |
| |                               | |
| |      __7__     %%%,%%%%%%%            | |
| |      \_._/      ,'%% \\-*%%%%%%%         | |
| |      ( ^ )   ;%%%%%*%  _%%%%            | |
| |      '='|\.  ,%%%    \(_.*%%%%.         | |
| |       / |  % *%%, ,%%%%*(  '          | |
| |      (/  | %^   ,*%%% )\|,%%*%,_         | |
| |      |__, |    *%  \/ #).-*%%*          | |
| |       |  |      _.) ,/ *%,           | |
| |       |  |  _________/)#(_____________       | |
| |       /___| |__________________________|       | |
| |       ===     [Win-Post-Install]         | |
| |_____________________________________________________________| |
|_________________________________________________________________|
          )__________|__|__________(
         |      ||      |
         |____________||____________|
          ),-----.(   ),-----.(
         ,'  ==.  \  / .==  '.
         /      ) (      \
         '==========='  '===========' 
"@

	"Monkey" = @"
            .="=.
           _/.-.-.\_   _
           ( ( o o ) )  ))
   .-------.    |/ " \|  //
   | WPI |    \'---'/  //
   _| GIT |_    /'"""'\\ ((
  =(_|_______|_)=  / /_,_\ \\ \\
   |:::::::::|   \_\\_'__/ \ ))
   |:::::::[]|    /' /'~\ |//
   |o=======.|   /  /  \ /
   '"""""""""' ,--',--'\/\  /
          '-- "--' '--'
"@

	"Windows_logo" = @"
 .----------------.
|     _    |
|   _.-'|'-._  |
| .__.|  |  | |
|   |_.-'|'-._| |
| '--'|  |  | |
| '--'|_.-'-'-._| |
| '--'       |
 '----------------'
"@

	"Windows_on_laptop" = @"
  ._________________.
  |.---------------.|
  ||  -._ .-.   ||
  ||  -._| | |  ||
  ||  -._|"|"|  ||
  ||  -._|.-.|  ||
  ||_______________||
  /.-.-.-.-.-.-.-.-.\
 /.-.-.-.-.-.-.-.-.-.\
 /.-.-.-.-.-.-.-.-.-.-.\
/______/__________\___o_\
\_______________________/
"@

	"Rocket_launch" = @"
     *         *         *       *
                           *       *
            *      *               ___
 *        *                     |   | |
    *       _________##         *    / \  | |
           @\\\\\\\\\##  *   |       |--o|===|-|
 *         @@@\\\\\\\\##\    \|/|/      |---|  | |
          @@ @@\\\\\\\\\\\  \|\\|//|/   *  /   \ | |
       *   @@@@@@@\\\\\\\\\\\  \|\|/|/     | W-P-I | | |
         @@@@@@@@@----------|  \\|//     | F-F  |=| |
    __     @@ @@@ @@__________|   \|/      | G-G  | | |
 ____|_@|_    @@@@@@@@@__________|   \|/      |_______| |_|
=|__ _____ |=   @@@@ .@@@__________|   |       |@| |@| | |
____0_____0__\|/__@@@@__@@@__________|_\|/__|___\|/__\|/___________|_|_
"@

	"Space_odyssey" = @"
                       _.--"""""--._
                     ,-'       '-.
        _            ,' --- - ----  --- '.
       ,'|'.          ,'    ________________'.
      O'.+,'O         /    /____(_______)___\ \
  _......_  ,=.     __________;  _____ ____ _____ _____ :
 ,'  ,--.-',,;,:,;;;;;;;///////////|  ----- ---- ----- ----- |
(  ( ==)=========================|   ,---.  ,---.  ,.  |
 '._ '--'-,''''''"""""""\\\\\\\\\\\:   /'. ,'\ /_  \ /\/\ ;
  ''''''              \  : Y : :-'-. : : ): /
                   '. \ | / \=====/ \/\/'
                    '. '-'-'  '---'  ;'
                     '-._      _,-'
                       '--.....--'  ,--.
                              ().0()
                              ''-'
"@

	"Galaxy" = @"
  .    .    .    .    .    .    .    .    .
   .     .     .    _......____._    .     .
  .     .     . ..--'"" .      """"""---...     .
          _...--""    ................    '-.       .
        .-'    ...:'::::;:::%:.::::::_;;:...   '-.
       .-'    ..::::'''''  _...---'"""":::+;_::.   '.   .
 .    .' .  ..::::'   _.-""        :::)::.    '.
     .   ..;:::'   _.-'     .       f::'::  o _
    /   .:::%' . .-"            .-. ::;;:.  /" "x
 .  .' ""::.::'  .-"   _.--'"""-.      (  ) ::.:: |_.-' |
   .'  ::;:'  .'   .-" .d@@b.  \  .  . '-'  ::%::  \_ _/  .
  .'  :,::'  /  . _'  8@@@@8  j   .-'    :::::   " o
  | . :.%:' . j   (_)  '@@@P' .'  .-"     ::.::  . f
  |  ::::   (    -..____...-' .-"     .::::'    /
.  |  ':'::  '.        ..--'    . .::'::  .  /
  j   ':::::  '-._____...---""       .::%:::'    .' .
   \   ::.:%..       .    .  ...:,::::'    .'
 .  \    ':::':..        ....::::.::::'    .-'     .
    \  .  '':::%::'::.......:::::%::.::::''    .-'
   . '.    . ''::::::%::::.::;;:::::'''   _.-'     .
 .    '-..   .  .  '''''''''     . _.-'   .     .
     .  ""--...____  .  ______......--' .     .     .
 .    .    .  """"""""   .    .    .    .    .
"@

		}

  $BannerGroups = @{
    "Window_Banners"  = @("Window_PS_Terminal", "Window_PS_Terminal_Old_Computer")
    "Windows_Banners" = @("Windows_logo", "Windows_on_laptop")
    "Space_Banners"  = @("Rocket_launch", "Space_odyssey", "Galaxy")
    "Misc_Banners"   = @("Monkey", "Teddy_Screen")
  }

  if ($BannerGroups.ContainsKey($BannerType)) {
    $selected = Get-Random -InputObject $BannerGroups[$BannerType]
    return $Banners[$selected]
  }

  if (-not $BannerType) {
    $selected = Get-Random -InputObject $Banners.Keys
    return $Banners[$selected]
  }

  return $Banners[$BannerType]
}


function Show-Banner {
  <#
  .SYNOPSIS
  Displays a selected or random banner with customizable color.

  .PARAMETER BannerType
  Optional. Specifies which banner to show. If not set, a random one is picked.

  .PARAMETER ForegroundColor
  Optional. The color used for displaying the banner. Defaults to Cyan.

  .EXAMPLE
  Show-Banner -BannerType "Monkey" -ForegroundColor Magenta
  #>

  param (
    [string]$BannerType = $(Get-Random -InputObject @(
      "Window_PS_Terminal",
      "Window_PS_Terminal_Old_Computer",
      "Teddy_Screen",
      "Monkey",
      "Windows_logo",
      "Windows_on_laptop",
      "Rocket_launch",
      "Space_odyssey",
      "Galaxy"
    )),
    [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
    [string]$ForegroundColor = "Cyan"
  )

  Get-Banner -BannerType $BannerType | Write-Host -ForegroundColor $ForegroundColor
}


<#
.SYNOPSIS
Retrieves basic system information.

.DESCRIPTION
Returns a custom object containing:
- The current timestamp
- The system's hostname
- The domain name (or WORKGROUP if not joined)

.OUTPUTS
[PSCustomObject] with Timestamp, Hostname, and Domain properties.
#>
function Get-SystemInfoData {
  $sysInfo = Get-CimInstance -ClassName Win32_ComputerSystem

  return [PSCustomObject]@{
    Timestamp = Get-Date -Format "M/d/yyyy h:mm:ss tt"
    Hostname = $env:COMPUTERNAME
    Domain  = if ($sysInfo.PartOfDomain) { $sysInfo.Domain } else { "WORKGROUP" }
  }
}


function Pause-ForUser {
  <#
  .SYNOPSIS
  Pauses script execution until the user presses Enter.

  .DESCRIPTION
  Displays a custom or default message prompting the user to press Enter to continue.

  .PARAMETER Message
  The message to display before waiting for user input. Defaults to "Press Enter to continue...".

  .EXAMPLE
  Pause-ForUser
  Pauses with the default message.

  .EXAMPLE
  Pause-ForUser -Message "Ready for the next step? Hit Enter."
  #>

  param (
    [string]$Message = "Press Enter to continue..."
  )

  Read-Host $Message
}


function ScriptExit {
  <#
  .SYNOPSIS
  Terminates the script execution with a given exit code.

  .DESCRIPTION
  Provides a unified and clean exit point for scripts. Displays a custom or default message
  unless the -NoExitMessage flag is specified.

  .PARAMETER ExitCode
  The exit code to terminate with. Default is 0 (success).

  .PARAMETER ExitMessage
  Optional custom message to display before exiting. If not specified, a default message is shown.

  .PARAMETER NoExitMessage
  If specified, suppresses all exit messages.

  .EXAMPLE
  ScriptExit -ExitCode 1 -ExitMessage "Fatal error during execution."

  .EXAMPLE
  ScriptExit # Exits with code 0 and default message.

  .EXAMPLE
  ScriptExit -ExitCode 2 -NoExitMessage # Exits silently with code 2.
  #>

  [CmdletBinding()]
  param (
    [Parameter(Position = 0)]
    [int]$ExitCode = 0,

    [Parameter(Position = 1)]
    [string]$ExitMessage,

    [switch]$NoExitMessage
  )

  if (-not $NoExitMessage) {
    if (-not $ExitMessage) {
      $ExitMessage = "Exiting script with exit code $ExitCode"
    }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if ($ExitCode -eq 0) {
      Write-Host "$ts - $ExitMessage" -ForegroundColor Green
    } else {
      Write-Host "$ts - $ExitMessage" -ForegroundColor Red
    }
  }

  exit $ExitCode
}


function Display-Help {
  [CmdletBinding()]
  <#
  .SYNOPSIS
  Displays the help menu for WinPostInstall.

  .DESCRIPTION
  This function prints a detailed help guide for the WinPostInstall PowerShell script, outlining its features, usage, and parameters.

  .EXAMPLE
  PS > .\WinPostInstall.ps1 -Help

  .LINK
  https://github.com/franckferman/WinPostInstall
  #>
  param()

  $helpText = @"
=======================================================
        WinPostInstall - Help Menu
=======================================================

DESCRIPTION:
WinPostInstall is a modular and automated post-installation script 
for customizing, configuring, and hardening Windows systems.

It is ideal for developers, cybersecurity professionals, and power users 
who want to streamline the setup of a clean Windows environment.

FEATURES:
 - Debloat Windows and disable telemetry
 - Harden the system using modern practices
 - Install tools and apps via WinGet & Microsoft Store
 - Configure developer environment (WSL, terminals, etc.)
 - Apply themes, privacy tweaks, and optimizations

USAGE:
Simply run the script in an elevated PowerShell session:

Example:
-------------------------------------------------------
PS > Set-ExecutionPolicy Bypass -Scope Process
PS > .\WinPostInstall.ps1
-------------------------------------------------------

PARAMETERS:
 -Help    Display this help menu.

REQUIREMENTS:
 - PowerShell 5.1 or later
 - Administrator privileges
 - Internet access for downloading tools and packages

CREDITS:
 - HardeningKitty   (https://github.com/scipag/HardeningKitty)
 - Win11Debloat    (https://github.com/Raphire/Win11Debloat)

SOURCE & UPDATES:
 GitHub Repository: https://github.com/franckferman/WinPostInstall

AUTHOR:
 Franck FERMAN
 contact@franckferman.fr

=======================================================
"@

  Write-Host ''
  Write-Host $helpText -ForegroundColor Cyan
  Write-Host ''
  ScriptExit
}


function Test-AdminRights {
  [CmdletBinding()]
  [OutputType([Bool])]
  param()

  <#
  .SYNOPSIS
  Tests if the current user has administrator rights.

  .DESCRIPTION
  This function will determine if the current user is part of the Administrator role. It utilizes the .NET classes for Windows Security and Principal Windows Built-in Roles to make this determination.

  .EXAMPLE
  if (Test-AdminRights) {
    Write-Host "You are running as an administrator."
  } else {
    Write-Host "You are not running as an administrator."
  }
  #>

  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
  $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

  return $principal.IsInRole($adminRole)
}


function Get-WANStatus {
  <#
  .SYNOPSIS
  Tests the WAN connection by trying to reach one of the provided URLs.

  .DESCRIPTION
  This function randomly selects one of the provided URLs (or default URLs if none are provided) and attempts to reach it.
  If successful, it returns "Online". Otherwise, it returns "Offline" or provides an error message.

  .PARAMETER urls
  An array of URLs to be tested. If none are provided, default URLs are used.

  .EXAMPLE
  Get-WANStatus -urls 'https://httpbin.org/get'
  #>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$false)]
    [System.Uri[]]$urls = @('https://httpbin.org/get', 'https://httpstat.us/200')
  )

  [String]$selectedUrl = Get-Random -InputObject $urls -Count 1
  $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

  try {
    $ProgressPreference = 'SilentlyContinue'
    $response = Invoke-WebRequest -Uri $selectedUrl -WebSession $webSession -Headers @{
      'User-Agent' = 'WinPostInstall/1.0.0'
    } -UseBasicParsing -TimeoutSec 5

    if ([Byte]$response.StatusCode -eq 200) {
      return "Online"
    } else {
      return "Offline - Received status code $($response.StatusCode)"
    }

  } catch {
    return "Offline - Error: $($_.Exception.Message)"
  }

}


<#
.SYNOPSIS
Retrieves the firewall "Enabled" status for the specified profiles.

.DESCRIPTION
Returns a list of objects showing whether the Windows Firewall is enabled
for each specified profile: Domain, Private, or Public.

.PARAMETER Profiles
An array of profile names to check. Valid values: Domain, Private, Public.
Defaults to all three.

.OUTPUTS
[PSCustomObject[]] with properties:
- Profile [string]
- Enabled [bool]
#>
function Get-FirewallEnabledStatus {
  param(
    [string[]]$Profiles = @("Domain", "Private", "Public")
  )

  $result = @()
  foreach ($profile in $Profiles) {
    $status = (Get-NetFirewallProfile -Profile $profile).Enabled
    $result += [PSCustomObject]@{
      Profile = $profile
      Enabled = $status
    }
  }
  return $result
}


<#
.SYNOPSIS
Retrieves the full firewall configuration state for the specified profiles.

.DESCRIPTION
Returns a list of custom objects with detailed firewall settings for each
profile, including enabled status, inbound/outbound actions, and rules.

.PARAMETER Profiles
An array of Windows Firewall profiles to query. Default: Domain, Private, Public.

.OUTPUTS
[PSCustomObject[]] with properties:
- Profile         [string]
- Enabled         [bool]
- DefaultInboundAction  [string]
- DefaultOutboundAction  [string]
- AllowInboundRules    [bool]
- AllowLocalFirewallRules [bool]
#>
function Get-FirewallProfileState {
  param(
    [string[]]$Profiles = @("Domain", "Private", "Public")
  )

  $result = @()
  foreach ($profile in $Profiles) {
    $fw = Get-NetFirewallProfile -Profile $profile
    $result += [PSCustomObject]@{
      Profile         = $profile
      Enabled         = $fw.Enabled
      DefaultInboundAction  = $fw.DefaultInboundAction
      DefaultOutboundAction  = $fw.DefaultOutboundAction
      AllowInboundRules    = $fw.AllowInboundRules
      AllowLocalFirewallRules = $fw.AllowLocalFirewallRules
    }
  }
  return $result
}


<#
.SYNOPSIS
Applies firewall hardening settings to the specified profiles.

.DESCRIPTION
Ensures that each profile has:
- The firewall enabled
- DefaultInboundAction set to Block
- DefaultOutboundAction set to Allow
- All inbound rules (including local ones) blocked

This function performs silent remediation without console output.
It is meant to be called from higher-level functions that handle display or logging.

.PARAMETER Profiles
The array of firewall profiles to harden. Default: Domain, Private, Public.

.INPUTS
[string[]]

.OUTPUTS
None (silent operation)
#>
function Apply-FirewallHardening {
  param(
    [string[]]$Profiles = @("Domain", "Private", "Public")
  )

  foreach ($profile in $Profiles) {
    $fw = Get-NetFirewallProfile -Profile $profile

    if ($fw.Enabled -ne "True") {
      Set-NetFirewallProfile -Profile $profile -Enabled "True"
    }
    if ($fw.DefaultInboundAction -ne "Block") {
      Set-NetFirewallProfile -Profile $profile -DefaultInboundAction Block
    }
    if ($fw.DefaultOutboundAction -ne "Allow") {
      Set-NetFirewallProfile -Profile $profile -DefaultOutboundAction Allow
    }
    if ($fw.AllowInboundRules -ne $false -or $fw.AllowLocalFirewallRules -ne $false) {
      Set-NetFirewallProfile -Profile $profile `
        -AllowInboundRules "False" `
        -AllowLocalFirewallRules "False"
    }
  }
}


<#
.SYNOPSIS
Displays the state of each Windows Firewall profile in a formatted table.

.PARAMETER State
The state object returned by Get-FirewallProfileState.

.OUTPUTS
None. Writes formatted output to the console.
#>
function Show-FirewallProfileState {
  param(
    [Parameter(Mandatory=$true)]
    $State
  )

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
  Write-Host "[👽] $ts - Current Firewall Profile Status" -ForegroundColor Cyan
  $State | Format-Table Profile, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules -AutoSize
}


<#
.SYNOPSIS
Executes the full firewall hardening process.

.DESCRIPTION
Audits the current firewall state, applies hardening,
and then displays the final result.
This function performs no direct console output by itself —
it delegates all display to Show-* functions.
#>
function Harden-AllFirewallProfiles {
  $profiles = @("Domain", "Private", "Public")
  $initialState = Get-FirewallProfileState -Profiles $profiles
  $finalState = $null

  Apply-FirewallHardening -Profiles $profiles

  $finalState = Get-FirewallProfileState -Profiles $profiles

  return [PSCustomObject]@{
    Initial = $initialState
    Final  = $finalState
  }
}


<#
.SYNOPSIS
Runs the full firewall hardening routine with output and user experience.

.DESCRIPTION
Displays header, system info, runs hardening, and shows before/after state.
This function manages the full UX.
#>
function Invoke-FirewallHardening {
  Write-Host "[👽] Auditing Firewall Profiles..." -ForegroundColor Cyan
  $results = Harden-AllFirewallProfiles

  Write-Host ""
  Show-FirewallProfileState -State $results.Initial

  Write-Host "[👽] Final Firewall Status:" -ForegroundColor Cyan
  Write-Host ""
  Show-FirewallProfileState -State $results.Final

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
  Write-Host "[👽] $ts - Hardening completed." -ForegroundColor Cyan
}


<#
.SYNOPSIS
A simple convenience function to call Invoke-FirewallHardening with an extra log.

.DESCRIPTION
Prints a starting message, then calls Invoke-FirewallHardening,
and optionally adds final logs or jokes.

.EXAMPLE
Harden-FirewallAndShowStatus
#>
function Harden-FirewallAndShowStatus {
    [CmdletBinding()]
    param()

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Starting firewall hardening..." -ForegroundColor Cyan
    Write-Host ""
    
    Invoke-FirewallHardening

$messages = @(
  "[🛡️] ...We sealed those open ports, but the NSA has a master key, allegedly.",
  "[🛡️] ...We sealed those open ports, but the NSA has a master key, allegedly.",
  "[🛡️] ...We sealed those open ports, but the NSA has a master key, allegedly.",

  "[🔒] ...Your firewall is now a fortress. If only the OS wasn't a secret passage.",
  "[🔒] ...Your firewall is now a fortress. If only the OS wasn't a secret passage.",
  "[🔒] ...Your firewall is now a fortress. If only the OS wasn't a secret passage.",

  "[👽] ...We locked the front door. Just be aware: Windows is named after windows for a reason.",
  "[👽] ...We locked the front door. Just be aware: Windows is named after windows for a reason.",
  "[👽] ...We locked the front door. Just be aware: Windows is named after windows for a reason.",

  "[🛸] ...Alien tech would never ship with hidden services. We tried our best to block them all.",
  "[🛸] ...Alien tech would never ship with hidden services. We tried our best to block them all."
  )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "[👽] $ts - Done. Secure as can be (until next Windows update)." -ForegroundColor Cyan
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


<#
.SYNOPSIS
Ensures the computer has a specific name.

.DESCRIPTION
Checks the current computer name. If it differs from the target name,
renames the computer (no automatic reboot). Returns an object with status info.

.PARAMETER DesiredName
Target computer name (default = 'root').

.OUTPUTS
[PSCustomObject] with properties: Renamed (bool), OldName, NewName, RequiresReboot (bool), Success (bool)
#>
function Ensure-ComputerName {
  param(
    [string]$DesiredName = "root"
  )

  $currentName = $env:COMPUTERNAME
  $result = [PSCustomObject]@{
    OldName    = $currentName
    NewName    = $DesiredName
    Renamed    = $false
    RequiresReboot = $false
    Success    = $true
  }

  if ($currentName -ieq $DesiredName) {
    return $result
  }

  try {
    Rename-Computer -NewName $DesiredName -Force -ErrorAction Stop
    $result.Renamed = $true
    $result.RequiresReboot = $true
  } catch {
    $result.Success = $false
  }

  return $result
}


<#
.SYNOPSIS
Displays the result of Ensure-ComputerName.

.PARAMETER Result
The result object returned from Ensure-ComputerName.
#>
function Show-ComputerNameChangeResult {
  param(
    [Parameter(Mandatory)]
    $Result
  )

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"

  if (-not $Result.Success) {
    Write-Host "[💀] $ts - Failed to rename computer from '$($Result.OldName)' to '$($Result.NewName)'." -ForegroundColor Red
    return
  }

  if (-not $Result.Renamed) {
    Write-Host "[👽] $ts - Computer name is already '$($Result.OldName)'." -ForegroundColor Green
  } else {
    Write-Host "[!] $ts - Renamed '$($Result.OldName)' to '$($Result.NewName)'. Reboot is required." -ForegroundColor Yellow
  }
}


function Ensure-ComputerNameAndShow {
  param([string]$DesiredName = "root")

  $result = Ensure-ComputerName -DesiredName $DesiredName
  Show-ComputerNameChangeResult -Result $result
}


<#
.SYNOPSIS
Ensures the computer has a specific description.

.DESCRIPTION
Checks the current 'SrvComment' in the registry. If it differs from the target,
updates it. Returns an object with status info.

.PARAMETER DesiredDescription
Target computer description to set. Default = "Alien Spaceship".

.OUTPUTS
[PSCustomObject] with properties: OldDescription, NewDescription, Changed, Success.

.EXAMPLE
Ensure-ComputerDescription

.EXAMPLE
Ensure-ComputerDescription -DesiredDescription "Laboratory #42"
#>
function Ensure-ComputerDescription {
  [CmdletBinding()]
  param(
    [string]$DesiredDescription = "Alien Spaceship"
  )

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
  Write-Host "[👽] $ts - Attempting to set the computer description to '$DesiredDescription'..." -ForegroundColor Cyan
  Write-Host ""

  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  $regValue = "SrvComment"

  $oldDesc = (Get-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue).$regValue

  $result = [PSCustomObject]@{
    OldDescription = $oldDesc
    NewDescription = $DesiredDescription
    Changed    = $false
    Success    = $true
  }

  if ($oldDesc -ieq $DesiredDescription) {
    return $result
  }

  try {
    Set-ItemProperty -Path $regPath -Name $regValue -Value $DesiredDescription -Force
    $result.Changed = $true
  }
  catch {
    $result.Success = $false
  }

  return $result
}


<#
.SYNOPSIS
Displays the result of Ensure-ComputerDescription.

.PARAMETER Result
The result object returned from Ensure-ComputerDescription.
#>
function Show-ComputerDescriptionChangeResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    $Result
  )

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"

  if (-not $Result.Success) {
    Write-Host "[💀] $ts - Failed to set computer description from '$($Result.OldDescription)' to '$($Result.NewDescription)'" -ForegroundColor Red
    return
  }

  if (-not $Result.Changed) {
    Write-Host "[👽] $ts - Computer description is already '$($Result.OldDescription)'." -ForegroundColor Green
  }
  else {
    Write-Host "[!] $ts - Updated computer description from '$($Result.OldDescription)' to '$($Result.NewDescription)'" -ForegroundColor Yellow
  }
}


function Ensure-ComputerDescriptionAndShow {
  param([string]$DesiredDescription = "Alien Spaceship")

  $result = Ensure-ComputerDescription -DesiredDescription $DesiredDescription
  Show-ComputerDescriptionChangeResult -Result $result
}


<#
.SYNOPSIS
Ensures the computer is in a specific workgroup.

.DESCRIPTION
- Checks if the computer is currently in a domain or already in the desired workgroup.
- If it's in a domain or a different workgroup, calls 'Add-Computer -WorkgroupName ...' to change it.
- Does not reboot automatically (you can add -Restart to Add-Computer if you want).
- Returns a [PSCustomObject] summarizing the operation.

.PARAMETER DesiredWorkgroup
The target workgroup name. Default is 'WORKGROUP'.

.OUTPUTS
[PSCustomObject] with:
- OldWorkgroup: current workgroup name (if in domain, it’s whatever Windows reports)
- NewWorkgroup: the requested one
- WasDomainJoined: boolean indicating if the machine was joined to a domain
- OldDomain: if joined to a domain, which one
- Changed: whether we actually changed the workgroup
- RequiresReboot: whether a reboot is needed to fully finalize changes
- Success: indicates if the operation succeeded
#>
function Ensure-Workgroup {
  [CmdletBinding()]
  param(
    [string]$DesiredWorkgroup = "WORKGROUP"
  )

  Write-Host "[👽] $ts - Attempting to set the computer's workgroup to '$DesiredWorkgroup'..." -ForegroundColor Cyan
  Write-Host ""

  $comp     = Get-CimInstance -ClassName Win32_ComputerSystem
  $oldWorkgroup = $comp.Workgroup
  $domain    = $comp.Domain
  $partOfDomain = $comp.PartOfDomain

  $result = [PSCustomObject]@{
    OldWorkgroup  = $oldWorkgroup
    NewWorkgroup  = $DesiredWorkgroup
    WasDomainJoined = $partOfDomain
    OldDomain    = if ($partOfDomain) { $domain } else { $null }
    Changed     = $false
    RequiresReboot = $false
    Success     = $true
  }

  if (-not $partOfDomain -and $oldWorkgroup -ieq $DesiredWorkgroup) {
    return $result
  }

  try {
    Add-Computer -WorkGroupName $DesiredWorkgroup -Force -ErrorAction Stop
    $result.Changed    = $true
    $result.RequiresReboot = $true
  }
  catch {
    $result.Success = $false
  }

  return $result
}


<#
.SYNOPSIS
Displays the result of Ensure-Workgroup.

.PARAMETER Result
The result object returned from Ensure-Workgroup.
#>
function Show-WorkgroupChangeResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    $Result
  )

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"

  if (-not $Result.Success) {
    Write-Host "[💀] $ts - Failed to switch workgroup. " -ForegroundColor Red
    if ($Result.WasDomainJoined) {
      Write-Host "    Machine was in domain '$($Result.OldDomain)'" -ForegroundColor Red
    }
    else {
      Write-Host "    Machine was in workgroup '$($Result.OldWorkgroup)'" -ForegroundColor Red
    }
    Write-Host "    Intended: '$($Result.NewWorkgroup)'" -ForegroundColor Red
    return
  }

  if (-not $Result.Changed) {
    Write-Host "[👽] $ts - Already in workgroup '$($Result.OldWorkgroup)'. No changes made." -ForegroundColor Green
  }
  else {
    if ($Result.WasDomainJoined) {
      Write-Host "[!] $ts - Removed from domain '$($Result.OldDomain)' to join workgroup '$($Result.NewWorkgroup)'. Reboot required." -ForegroundColor Yellow
    }
    else {
      Write-Host "[!] $ts - Changed workgroup from '$($Result.OldWorkgroup)' to '$($Result.NewWorkgroup)'. Reboot required." -ForegroundColor Yellow
    }
  }
}


function Ensure-WorkgroupAndShow {
  param([string]$DesiredWorkgroup = "WORKGROUP")

  $result = Ensure-Workgroup -DesiredWorkgroup $DesiredWorkgroup
  Show-WorkgroupChangeResult -Result $result
}


function Set-DisplayExtendBottomTop {
  <#
  .SYNOPSIS
  Opens the DisplaySwitch GUI and simulates keystrokes to extend display (dual-screen) mode.

  .DESCRIPTION
  This function launches DisplaySwitch.exe, waits for the UI to load, navigates using simulated keystrokes to select the "Extend" display mode,
  confirms it with ENTER, then closes the window with ESC.

  NOTE: Windows does not provide a CLI option to control screen positions (e.g., screen 1 below screen 2), but you can extend displays with this.

  .OUTPUTS
  Console messages with status.
  #>

  Add-Type -AssemblyName System.Windows.Forms

  try {
    Write-Host "[👽] Launching DisplaySwitch to change display mode..." -ForegroundColor Cyan
    Start-Process "DisplaySwitch.exe"
    Start-Sleep -Seconds 2

    Write-Host "[👽] Navigating to 'Extend display' mode..." -ForegroundColor Cyan
    [System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
    Start-Sleep -Milliseconds 400

    [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
    Start-Sleep -Milliseconds 400

    Write-Host "[👽] Closing DisplaySwitch UI..." -ForegroundColor Cyan
    [System.Windows.Forms.SendKeys]::SendWait("{ESC}")

    Write-Host "[👽] Display mode should now be set to 'Extend'." -ForegroundColor Green
  } catch {
    Write-Host "[💀] Failed to switch display mode: $($_.Exception.Message)" -ForegroundColor Red
  }
}


function Enable-RequiredFeatures {
<#
.SYNOPSIS
Enables specific required Windows features.

.DESCRIPTION
Iterates through a list of features, enabling each if not already active.
By default, targets:
- Hyper-V
- Virtual Machine Platform
- Windows Hypervisor Platform
- Windows Sandbox
- Windows Subsystem for Linux

.PARAMETER FeatureList
An array of feature names to enable. Defaults to common virtualization and WSL requirements.

.EXAMPLE
Enable-RequiredFeatures

.EXAMPLE
Enable-RequiredFeatures -FeatureList @("Microsoft-Windows-Subsystem-Linux", "HypervisorPlatform")
#>
    [CmdletBinding()]
    param(
        [string[]]$FeatureList = @(
            "HypervisorPlatform",
            "Microsoft-Hyper-V-All",
            "Microsoft-Hyper-V-Tools-All",
            "VirtualMachinePlatform",
            "Containers-DisposableClientVM",
            "Microsoft-Windows-Subsystem-Linux"
        )
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Initiating enabling of required Windows features..." -ForegroundColor Cyan
    Write-Host ""

    foreach ($feature in $FeatureList) {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $featureInfo = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue

        if (-not $featureInfo) {
            Write-Host "[!] $ts - Feature '$feature' not available on this system." -ForegroundColor Yellow
            continue
        }

        if ($featureInfo.State -eq "Enabled") {
            Write-Host "[👽] $ts - Feature '$feature' already enabled." -ForegroundColor Green
        }
        else {
            Write-Host "[👽] $ts - Enabling feature '$feature'..." -ForegroundColor Cyan
            try {
                Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart -ErrorAction Stop | Out-Null
                Write-Host "[✔️] $ts - Feature '$feature' enabled successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "[💀] $ts - Failed to enable '$feature': $_" -ForegroundColor Red
            }
        }
    }

    $messages = @(
	    "[🛸] ...'The DGSI thanks you for enabling surveillance in isolated environments.",
	    "[🛸] ...'The DGSI thanks you for enabling surveillance in isolated environments.",
	    "[🛸] ...'The DGSI thanks you for enabling surveillance in isolated environments.",

	    "[📡] ...Virtual machine platform ready. The NSA just got a new viewport.",
	    "[📡] ...Virtual machine platform ready. The NSA just got a new viewport.",
	    "[📡] ...Virtual machine platform ready. The NSA just got a new viewport.",

	    "[🧠] ...Windows Sandbox enabled. Like Schrödinger’s PC: infected *and* clean at once.",
	    "[🧠] ...Windows Sandbox enabled. Like Schrödinger’s PC: infected *and* clean at once.",

        "[📦] ...Enabled WSL. Microsoft smiles. The penguin watches silently.",
        "[🛰️] ...WSL enabled. Satellite uplink initiated. Good job, agent.",
        "[📜] ...You enabled legacy support. Windows will now run like it’s 2004. Including the vulnerabilities.",
        "[👽] ...Congratulations. You've successfully virtualized your problems.",
        "[📦] ...WSL active. Enjoy Linux. Under Windows. Overseen by Azure. Observed by everyone.",
        "[🤫] ...Virtual machines are now possible. Unlike privacy on Windows."
    )

    Write-Host ""
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Required features activation completed." -ForegroundColor Green
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Disable-UnneededFeatures {
<#
.SYNOPSIS
Disables specific unneeded Windows features.

.DESCRIPTION
Iterates through a provided list of Windows features, disabling each if it is currently active.
By default, targets:
- MediaPlayback
- Printing-PrintToPDFServices-Features
- Print-Services
- Printing-Foundation-Features
- Printing-Foundation-InternetPrinting-Client
- MSRDC-Infrastructure
- SmbDirect
- WorkFolders-Client

.PARAMETER FeatureList
Array of Windows Feature names to disable. Defaults to a known set of unneeded features.

.EXAMPLE
Disable-UnneededFeatures

.EXAMPLE
Disable-UnneededFeatures -FeatureList @("MediaPlayback", "SmbDirect", "WorkFolders-Client")
#>
    [CmdletBinding()]
    param(
        [string[]]$FeatureList = @(
            "MediaPlayback",
            "Printing-PrintToPDFServices-Features",
            "Print-Services",
            "Printing-Foundation-Features",
            "Printing-Foundation-InternetPrinting-Client",
            "MSRDC-Infrastructure",
            "SmbDirect",
            "WorkFolders-Client"
        )
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Initiating removal of unneeded Windows features..." -ForegroundColor Cyan
    Write-Host ""

    foreach ($feature in $FeatureList) {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $featureInfo = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue

        if (-not $featureInfo) {
            Write-Host "[!] $ts - Feature '$feature' not available on this system." -ForegroundColor Yellow
            continue
        }

        if ($featureInfo.State -eq "Disabled") {
            Write-Host "[👽] $ts - Feature '$feature' already disabled." -ForegroundColor Green
        }
        else {
            Write-Host "[👽] $ts - Disabling feature '$feature'..." -ForegroundColor Cyan
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
                Write-Host "[👽] $ts - Feature '$feature' disabled successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "[!] $ts - Failed to disable '$feature': $_" -ForegroundColor Red
            }
        }
    }

	$messages = @(
	  "[🦖] ...'Print Services'? What is this, 1997? Do you also fax your memes?",
	  "[🦖] ...'Print Services'? What is this, 1997? Do you also fax your memes?",
	  "[🦖] ...'Print Services'? What is this, 1997? Do you also fax your memes?",

	  "[🛰️] ...Less clutter. The DGSI might be impressed. Or suspicious.",
	  "[🛰️] ...Less clutter. The DGSI might be impressed. Or suspicious.",
	  "[🛰️] ...Less clutter. The DGSI might be impressed. Or suspicious.",

	  "[🫣] ...Less clutter. The NSA might be impressed. Or suspicious.",
	  "[🫣] ...Less clutter. The NSA might be impressed. Or suspicious.",
	  "[🫣] ...Less clutter. The NSA might be impressed. Or suspicious.",

	  "[📜] ...Obsolete Windows features removed. Now let's talk about the EULA from 2003.",
	  "[📜] ...Obsolete Windows features removed. Now let's talk about the EULA from 2003.",

	  "[🛠] ...We removed those dusty features – let's hope Windows doesn't get lonely.",
	  "[🤡] ...No more Print Services. Because who prints in 2025? The watchers do, ironically.",
	  "[👁️] ...We disabled Remote Differential Compression. Sorry NSA, no more sneaky deltas.",
	  "[🕵️] ...You turned off unused features. Microsoft turned on its interest in you.",
	  "[🚪] ...We closed some old doors. Sadly, Windows left all the windows open.",
	  "[🫥] ...We removed the features. Windows kept the telemetry. Fair trade?",
	  "[📼] ...We disabled Media Playback. Millennials everywhere rejoice."
	)

	Write-Host ""
	$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	Write-Host "[👽] $ts - Unneeded Windows features removal completed." -ForegroundColor Green
	Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


<#
.SYNOPSIS
Installs the NuGet package provider.

.DESCRIPTION
Installs the NuGet provider required for installing PowerShell modules.
#>
function Install-NuGETProvider {
  Write-Host "[👽] $ts - Installing NuGet provider." -ForegroundColor Green
  try {
    Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
    Write-Host ""
    Write-Host "[👽] $ts - NuGet provider installation completed." -ForegroundColor Green
  } catch {
    Write-Host "[!] $ts - Failed to install NuGet provider: $_" -ForegroundColor Red
  }
}


function Install-MSStoreAppByName {
  <#
  .SYNOPSIS
  Installs one or more Microsoft Store apps by name using winget.

  .DESCRIPTION
  Handles names with spaces and selects correct matches intelligently even among similar results.

  .PARAMETER AppList
  An array of app names to search and install.

  .EXAMPLE
  Install-MSStoreAppByName -AppList @("Netflix", "MSI Center", "Lively Wallpaper")
  #>

  param(
    [Parameter(Mandatory = $true)]
    [string[]]$AppList
  )

  foreach ($AppName in $AppList) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "[👽] $ts - Searching for: $AppName" -ForegroundColor Cyan

    $quotedAppName = "`"$AppName`""
    $searchResults = winget search --name $quotedAppName --disable-interactivity --accept-source-agreements --source msstore 2>&1 |
      Select-String -Pattern "^\s*([^\s].*?)\s+([0-9A-Z]{10,})"

    if (-not $searchResults) {
      Write-Host "[!] $ts - No results found for '$AppName'." -ForegroundColor Red
      continue
    }

    # Cherche un nom qui commence EXACTEMENT par $AppName
    $cleanMatches = $searchResults | Where-Object {
      $line = $_.ToString().Trim()
      $line -match "^\s*(.+?)\s+([0-9A-Z]{10,})" -and
      ($matches[1] -eq $AppName -or $matches[1].StartsWith($AppName))
    }

    if ($cleanMatches.Count -eq 0) {
      Write-Host "[!] $ts - No clean match for '$AppName'." -ForegroundColor Yellow
      continue
    }

    # On prend le premier match proprement
    $line = $cleanMatches[0].ToString().Trim()
    $name = ($line -split "\s{2,}")[0]
    $id  = ($line -split "\s{2,}")[-1]

    Write-Host "[👽] $ts - Installing $name [$id]..." -ForegroundColor Green

    try {
      winget install --id $id `
              --source msstore `
              --accept-package-agreements `
              --accept-source-agreements `
              --silent
      Write-Host "[👽] $ts - Installed $name" -ForegroundColor Green
    } catch {
      Write-Host "[💀] $ts - Failed to install $name" -ForegroundColor Red
    }
  }
}


function Install-MSStoreAppById {
  <#
  .SYNOPSIS
  Installs one or more Microsoft Store apps using their unique IDs via winget.

  .DESCRIPTION
  Uses winget with a specific ID. Verifies success by checking exit code.

  .PARAMETER AppIdList
  One or more App IDs to install.

  .EXAMPLE
  Install-MSStoreAppById -AppIdList @("9PLFNLNT3G5G", "ModernFlyouts.ModernFlyouts")
  #>

  param(
    [Parameter(Mandatory = $true)]
    [string[]]$AppIdList
  )

  foreach ($AppId in $AppIdList) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "[👽] $ts - Installing from ID: $AppId" -ForegroundColor Cyan

    $process = Start-Process winget -ArgumentList @(
      'install',
      '--id', "$AppId",
      '--source', 'msstore',
      '--accept-package-agreements',
      '--accept-source-agreements',
      '--silent'
    ) -Wait -PassThru -NoNewWindow

    if ($process.ExitCode -eq 0) {
      Write-Host "[👽] $ts - Successfully installed $AppId" -ForegroundColor Green
    } else {
      Write-Host "[💀] $ts - Failed to install $AppId (Exit code: $($process.ExitCode))" -ForegroundColor Red
    }
  }
}


<#
.SYNOPSIS
Installs Windows updates using PSWindowsUpdate module.

.DESCRIPTION
Installs the required module, accepts all available updates,
and installs them without rebooting.
#>
function Install-WindowsUpdates {
  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
  Write-Host "[👽] $ts - Running Windows Update process..." -ForegroundColor Cyan

  try {
    Install-Module -Name PSWindowsUpdate -Force -ErrorAction Stop
    $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
    Write-Host "[👽] $ts - PSWindowsUpdate module installed successfully." -ForegroundColor Green
  } catch {
    $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
    Write-Host "[!] $ts - Failed to install PSWindowsUpdate module: $_" -ForegroundColor Red
    return
  }

  try {
    $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
    Write-Host "[👽] $ts - Scanning for updates..." -ForegroundColor Cyan
    Get-WindowsUpdate -Confirm:$false -AcceptAll

    $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
    Write-Host ""
    Write-Host "[👽] $ts - Installing all available updates..." -ForegroundColor Cyan
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Confirm:$false -IgnoreReboot

    $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
    Write-Host ""
    Write-Host "[👽] $ts - Windows updates installed successfully." -ForegroundColor Green
  } catch {
    $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
    Write-Host "[!] $ts - Windows Update process failed: $_" -ForegroundColor Red
  }
}


<#
.SYNOPSIS
Configures a custom power profile optimized for performance and stability.

.DESCRIPTION
- Creates a custom power scheme based on "High Performance".
- Disables display, standby, and hibernate timeouts.
- Enables hibernation and hybrid sleep.
- Keeps processor idle and disk sleep to preserve efficiency.

.OUTPUTS
Console messages for each step.
#>
function Set-PowerSettings {
  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
  Write-Host "[👽] $ts - Applying custom Power Management settings..." -ForegroundColor Cyan
  Write-Host ""

  try {
		# Duplicate the High Performance profile
		$rawGuid = powercfg.exe -duplicatescheme SCHEME_MIN
		$guid = ($rawGuid | Select-String -Pattern 'Power Scheme GUID:\s*([a-f0-9-]{36})').Matches.Groups[1].Value

		powercfg.exe /changename $guid "Performance"
		powercfg.exe /setactive $guid
		Write-Host "[👽] $ts - Custom 'Performance' profile created and activated." -ForegroundColor Green

    # Disable monitor timeout
    powercfg.exe /change monitor-timeout-ac 0
    # powercfg.exe /change monitor-timeout-dc 0
    powercfg.exe /change monitor-timeout-dc 120
    # Write-Host "[👽] $ts - Monitor timeout disabled." -ForegroundColor Green
		Write-Host "[👽] $ts - Monitor timeout set: AC=never, DC=2h." -ForegroundColor Green

    # Disable sleep/standby
    powercfg.exe /change standby-timeout-ac 0
    powercfg.exe /change standby-timeout-dc 0
    Write-Host "[👽] $ts - Sleep timeout disabled." -ForegroundColor Green

    # Disable hibernate timeout (but keep hibernation itself)
    powercfg.exe /change hibernate-timeout-ac 0
    powercfg.exe /change hibernate-timeout-dc 0
    Write-Host "[👽] $ts - Hibernate timeout disabled." -ForegroundColor Green

    # Enable hibernation (used for hybrid sleep)
    powercfg.exe /hibernate on
    Write-Host "[👽] $ts - Hibernation enabled." -ForegroundColor Green

    # Enable hybrid sleep
    powercfg.exe /setacvalueindex $guid SUB_SLEEP HYBRIDSLEEP 1
    powercfg.exe /setdcvalueindex $guid SUB_SLEEP HYBRIDSLEEP 1
    Write-Host "[👽] $ts - Hybrid sleep enabled." -ForegroundColor Green

    # Ensure processor idle states are allowed (keeps CPU efficient)
    powercfg.exe /setacvalueindex $guid SUB_PROCESSOR PROCTHROTTLEMAX 100
    powercfg.exe /setacvalueindex $guid SUB_PROCESSOR IDLEDISABLE 0
    Write-Host "[👽] $ts - CPU idle states preserved." -ForegroundColor Green

    # Enable disk sleep after 20 mins on battery (0 = never on AC)
    powercfg.exe /change disk-timeout-ac 0
    powercfg.exe /change disk-timeout-dc 20
    Write-Host "[👽] $ts - Disk sleep configured (never on AC, 20 mins on battery)." -ForegroundColor Green
  }
  catch {
    Write-Host "[!] $ts - Failed to configure power settings: $($_.Exception.Message)" -ForegroundColor Red
  }
}


function Old-Install-WingetApplications {
  <#
  .SYNOPSIS
  Installs or updates a list of applications via Winget (by ID).

  .DESCRIPTION
  - Checks if each application is installed.
  - If installed, checks if upgrade is available.
  - Installs only if needed.
  - Clean and silent output.

  .PARAMETER AppList
  List of Winget package IDs.
  #>

  param (
    [Parameter(Mandatory = $true)]
    [string[]]$AppList
  )

  foreach ($appId in $AppList) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "[👽] $ts - Checking: $appId" -ForegroundColor Cyan

    $isInstalled = winget list --id "$appId" --accept-source-agreements --disable-interactivity | Select-String "$appId"

    if (-not $isInstalled) {
      Write-Host "[👽] $ts - Not installed. Proceeding with installation..." -ForegroundColor Yellow
    } else {
      # App is installed, check if upgrade is available
      $upgradeCheck = winget upgrade --id "$appId" --accept-source-agreements --disable-interactivity | Select-String "$appId"

      if (-not $upgradeCheck) {
        Write-Host "[✅] $ts - Already installed and up-to-date: $appId" -ForegroundColor Green
        continue
      }

      Write-Host "[👽] $ts - Update available. Proceeding with upgrade..." -ForegroundColor Cyan
    }

    try {
      winget install --id "$appId" `
              --accept-package-agreements `
              --accept-source-agreements `
              --silent `
              --force

      Write-Host "[✅] $ts - Successfully installed or updated: $appId" -ForegroundColor Green
    }
    catch {
      $code = $_.Exception.HResult
      Write-Host "[💀] $ts - Failed to install: $appId (Exit code: $code)" -ForegroundColor Red
    }
  }
}


function Install-WingetApplications {
  <#
  .SYNOPSIS
  Installs or updates a list of applications via Winget (by ID).
  
  .DESCRIPTION
  - Checks if each application is installed.
  - If installed, checks if upgrade is available.
  - Installs only if needed.
  - Retries a few times in case of connectivity issues (e.g., WinHttpSendRequest: 12007).
  
  .PARAMETER AppList
  List of Winget package IDs.

  .PARAMETER MaxRetries
  Number of retries if the installation fails due to connectivity errors.

  .PARAMETER RetryWaitTime
  Waiting time in seconds between each retry attempt.

  .EXAMPLE
  Install-WingetApplications -AppList @("Mozilla.Firefox","GIMP.GIMP") -MaxRetries 3 -RetryWaitTime 5
  #>

  param (
    [Parameter(Mandatory = $true)]
    [string[]]$AppList,

    [int]$MaxRetries = 3,
    [int]$RetryWaitTime = 5
  )

  foreach ($appId in $AppList) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "[👽] $ts - Checking: $appId" -ForegroundColor Cyan

    # Vérifie si installé
    $isInstalled = winget list --id "$appId" --accept-source-agreements --disable-interactivity | Select-String "$appId"

    if (-not $isInstalled) {
      Write-Host "[👽] $ts - Not installed. Proceeding with installation..." -ForegroundColor Yellow
      $needsInstall = $true
    }
    else {
      $upgradeCheck = winget upgrade --id "$appId" --accept-source-agreements --disable-interactivity | Select-String "$appId"

      if (-not $upgradeCheck) {
        Write-Host "[✅] $ts - Already installed and up-to-date: $appId" -ForegroundColor Green
        continue
      }
      Write-Host "[👽] $ts - Update available. Proceeding with upgrade..." -ForegroundColor Cyan
      $needsInstall = $true
    }

    if ($needsInstall) {
      $success = $false

      for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-Host "[👽] $ts - Attempt $attempt/$MaxRetries for $appId..." -ForegroundColor DarkCyan

        try {
          winget install --id "$appId" `
                  --accept-package-agreements `
                  --accept-source-agreements `
                  --silent `
                  --force

          Write-Host "[✅] $ts - Successfully installed or updated: $appId" -ForegroundColor Green
          $success = $true
          break
        }
        catch {
          $code = $_.Exception.HResult
          $msg = $_.Exception.Message

          Write-Host "[💀] $ts - Failed to install: $appId (Exit code: $code)" -ForegroundColor Red
          Write-Host "    Error message: $msg" -ForegroundColor DarkRed

          # Si c'est l'erreur 12007 (DNS), on retente, sinon on peut abandonner direct.
          if ($msg -like "*12007*") {
            if ($attempt -lt $MaxRetries) {
              Write-Host "[⚠] Will retry in $RetryWaitTime seconds..." -ForegroundColor Yellow
              Start-Sleep -Seconds $RetryWaitTime
            }
            else {
              Write-Host "[💥] No more retries left for $appId. Aborting." -ForegroundColor Red
            }
          }
          else {
            # Autre erreur => on arrête tout de suite (pas de retry).
            break
          }
        }
      }

      if (-not $success) {
        Write-Host "[❌] $ts - Could not install $appId after $MaxRetries attempts." -ForegroundColor Magenta
      }
    }
  }
}


<#
.SYNOPSIS
Adds specified paths to the user's PATH environment variable.

.DESCRIPTION
Accepts a list of paths as input. For each path, it checks if it's already in the PATH.
If not, verifies the path exists in the filesystem, then adds it and shows a timestamped log.

.PARAMETER Paths
Array of paths to add to the PATH variable. Use -List as alias.

.EXAMPLE
Alter-PathVariable -Paths @("C:\Tools", "C:\Go\bin")

.EXAMPLE
$customPaths = "C:\X", "C:\Y"; Alter-PathVariable -List $customPaths
#>

function Alter-PathVariable {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias("List")]
    [string[]]$Paths
  )

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Starting to add custom paths to the user's PATH..." -ForegroundColor Cyan
  Write-Host ""

  $CurrentPATH = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User).Split(";") |
    ForEach-Object { $_.Trim() }

  foreach ($path in $Paths) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    try {
      $normalized = [System.IO.Path]::GetFullPath($path)
    }
    catch {
      Write-Host "[!] $ts - Invalid path format: $path" -ForegroundColor Red
      continue
    }

    if (-not (Test-Path $normalized)) {
      Write-Host "[!] $ts - Path does not exist on disk: $normalized" -ForegroundColor Yellow
      continue
    }

    if ($CurrentPATH -contains $normalized) {
      Write-Host "[!] $ts - Path already exists: $normalized" -ForegroundColor Green
    }
    else {
      try {
        $NewPATH = ($CurrentPATH + $normalized) -join ";"
        [Environment]::SetEnvironmentVariable("PATH", $NewPATH, [EnvironmentVariableTarget]::User)

        Write-Host "[👽] $ts - Added path: $normalized" -ForegroundColor Cyan
      }
      catch {
        Write-Host "[!] $ts - Failed to add path: $normalized. Error: $_" -ForegroundColor Red
      }
    }
  }
}


<#
.SYNOPSIS
Sets humorous OEM information in the Windows registry.

.DESCRIPTION
Modifies (creates or updates) the OEM information displayed in Windows System properties 
with amusing (or custom) values. Requires running in an elevated (admin) PowerShell session,
as it writes to HKLM:\.

.PARAMETER Manufacturer
OEM manufacturer string displayed in System properties.

.PARAMETER SupportPhone
Support phone number displayed.

.PARAMETER Model
Model string displayed.

.PARAMETER SupportURL
Support URL displayed.

.PARAMETER SupportHours
Support hours displayed.

.PARAMETER HelpCustomized
Binary flag to indicate custom help.

.EXAMPLE
Set-OEMInformation

.EXAMPLE
Set-OEMInformation -Manufacturer "NSA" -Model "Snowden 2600"
#>

function Set-OEMInformation {
  [CmdletBinding()]
  param (
    [string]$Manufacturer  = "Direction Générale de la Surveillance Intérieure (DGSI)",
    [string]$SupportPhone  = "0 800 005 696",
    [string]$Model     = "UFO 🛸 HyperSpeed * Edition Area 51 👽 Technologies",
    [string]$SupportURL   = "https://intranet.dgsi.gouv",
    [string]$SupportHours  = "24/7 (Surveillance continue) - Whenever we're not abducting cows 🐄",
    [int]  $HelpCustomized = 1
  )

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Applying custom OEM information to Windows System properties..." -ForegroundColor Cyan
  Write-Host ""

  $OEMRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\OEMInformation"

  $OEMData = @{
    Manufacturer  = $Manufacturer
    SupportPhone  = $SupportPhone
    Model     = $Model
    SupportURL   = $SupportURL
    SupportHours  = $SupportHours
    HelpCustomized = $HelpCustomized
  }

  if (Test-Path $OEMRegPath) {
    Write-Host "[i] Key 'OEMInformation' already exists. Updating existing OEM info..." -ForegroundColor Cyan
  }
  else {
    try {
      New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion" -Name "OEMInformation" -Force | Out-Null
      Write-Host "[i] Key 'OEMInformation' created." -ForegroundColor Cyan
    }
    catch {
      Write-Host "[!] Unable to create registry key: $($OEMRegPath). Error: $_" -ForegroundColor Red
      return
    }
  }

  foreach ($key in $OEMData.Keys) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
      Set-ItemProperty -Path $OEMRegPath -Name $key -Value $OEMData[$key] -Force
      Write-Host "[👽] $ts - Set OEM property '$key' to '$($OEMData[$key])'" -ForegroundColor Green
    }
    catch {
      Write-Host "[!] $ts - Failed to set OEM property '$key'. Error: $_" -ForegroundColor Red
      return
    }
  }

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host ""
  Write-Host "[👽] $ts - OEM Information successfully applied." -ForegroundColor Cyan
}


<#
.SYNOPSIS
Disables telemetry and diagnostic data collection on Windows.

.DESCRIPTION
Sets multiple registry keys to disable Windows telemetry and feedback notifications for enhanced privacy.
Requires running PowerShell as Administrator (elevated) to modify HKLM:\ paths.

.OUTPUTS
None. Provides console output with status indicators.

.EXAMPLE
Disable-Telemetry
#>
function Disable-Telemetry {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
  Write-Host "[👽] $ts - Disabling Windows Telemetry and diagnostics..." -ForegroundColor Cyan
  Write-Host ""

  $registryPaths = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
    @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "LimitEnhancedDiagnosticDataWindowsAnalytics"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications"; Value = 1 }
  )

  foreach ($reg in $registryPaths) {
    try {
      if (-not (Test-Path $reg.Path)) {
        New-Item -Path $reg.Path -Force | Out-Null
      }

      Set-ItemProperty -Path $reg.Path -Name $reg.Name -Type DWord -Value $reg.Value -Force

      Write-Host "[*] $ts - Successfully set '$($reg.Name)' in '$($reg.Path)' to '$($reg.Value)'." -ForegroundColor Cyan
    }
    catch {
      Write-Host "[!] $ts - Failed to set '$($reg.Name)' in '$($reg.Path)'. Error: $_" -ForegroundColor Red
    }
  }

$messages = @(
  "[🪙] ...you disabled telemetry. Brave. Still sold your soul for a license though.",
  "[🪙] ...you disabled telemetry. Brave. Still sold your soul for a license though.",
  "[🪙] ...you disabled telemetry. Brave. Still sold your soul for a license though.",

  "[🔍] ...but Windows Search still logs your every keystroke. Just saying.",
  "[🔍] ...but Windows Search still logs your every keystroke. Just saying.",
  "[🔍] ...but Windows Search still logs your every keystroke. Just saying.",

  "[🫣] ...I mean, as much privacy as you can have on Windows.",
  "[🫣] ...I mean, as much privacy as you can have on Windows.",
  "[🫣] ...I mean, as much privacy as you can have on Windows.",

  "[🛰️] ...but the NSA might still wave 👋",
  "[🛰️] ...but the NSA might still wave 👋",

  "[💡] ...but let's be honest, you still live in a house with transparent walls.",
  "[💡] ...but let's be honest, you still live in a house with transparent walls.",

  "[🤡] ...until you open OneDrive.",
  "[🕵️] ...but Cortana probably still knows what you did last summer.",
  "[🧠] ...don’t worry, Clippy is no longer watching. Or is he?",
  "[📡] ...some packets just want to be free. Like telemetry packets.",
  "[🪟] ...you can close the window, but you’re still inside the house.",
  "[💾] ...remember: disabling telemetry doesn't delete what was already sent.",
  "[👀] ...you unplugged the camera, but the mic says hi.",
  "[🎤] ...you muted the mic. Microsoft unmuted your trust.",
  "[📦] ...but the bloatware already knows your secrets.",
  "[☁️] ...and somewhere in the cloud, a data center sheds a tear.",
  "[🧻] ...privacy policies are like toilet paper. Nice to have, mostly symbolic.",
  "[🛸] ...alien technology would never ship with Windows Update."
)

Write-Host ""
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "[👽] $ts - Telemetry has been disabled. Your privacy is (somewhat) restored." -ForegroundColor Green
Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Install-MSI {
  <#
  .SYNOPSIS
  Installs one or more .msi files silently with logs *

  .PARAMETER MSIPaths
  One or more paths (relative or absolute) to .msi files

  .EXAMPLE
  Install-MSI -MSIPaths ".\src\softwares\wsl_update_x64.msi"
  .EXAMPLE
  Install-MSI -MSIPaths @(".\src\softwares\file1.msi", ".\src\softwares\file2.msi")
  #>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string[]]$MSIPaths
  )

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
  Write-Host "[👽] $ts - Beginning MSI installation process..." -ForegroundColor Cyan
  Write-Host ""

  foreach ($path in $MSIPaths) {
    $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
    $resolved = Resolve-Path $path -ErrorAction SilentlyContinue

    if (-not $resolved) {
      Write-Host "[!] $ts - File not found: $path" -ForegroundColor Red
      continue
    }

    $absolutePath = $resolved.Path
    $ext = [System.IO.Path]::GetExtension($absolutePath)

    if ($ext -ne ".msi") {
      Write-Host "[⚠️] $ts - Not an MSI file: $absolutePath. Skipping." -ForegroundColor Yellow
      continue
    }

    $logFile = "$env:TEMP\Install-$(Split-Path $absolutePath -Leaf).log"

    Write-Host "[*] $ts - Installing MSI: $absolutePath" -ForegroundColor Cyan

    try {
      Start-Process msiexec.exe `
        -ArgumentList "/i `"$absolutePath`" /quiet /norestart /log `"$logFile`"" `
        -Wait -NoNewWindow

      $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
      Write-Host "[✔️] $ts - Successfully installed: $absolutePath" -ForegroundColor Green
    }
    catch {
      $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
      Write-Host "[💀] $ts - Failed to install: $absolutePath. Error: $_" -ForegroundColor Red
      Write-Host "   → Check log: $logFile" -ForegroundColor DarkGray
    }
  }
}


function Register-WSLMSIInstallOnBoot {
  param (
    [Parameter(Mandatory = $true)]
    [string]$MSIPath
  )

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $resolved = Resolve-Path $MSIPath -ErrorAction SilentlyContinue

  if (-not $resolved) {
    Write-Host "[💀] $ts - File not found: $MSIPath" -ForegroundColor Red
    return
  }

  $absolutePath = $resolved.Path
  $baseFolder  = "C:\WinPostInstall\InstallWSL"
  $msiDest   = Join-Path $baseFolder (Split-Path $absolutePath -Leaf)
  $psScriptPath = Join-Path $baseFolder "InstallWSL.ps1"
  $taskName   = "WinPostInstall_WSL"

  $taskExists = schtasks /Query /TN $taskName /FO LIST /ErrorAction SilentlyContinue 2>$null
  if ($taskExists) {
    Write-Host "[⚠️] $ts - Scheduled task '$taskName' already exists. Aborting." -ForegroundColor Yellow
    return
  }

  if (Test-Path $psScriptPath) {
    Write-Host "[⚠️] $ts - Script already exists: $psScriptPath" -ForegroundColor Yellow
    Write-Host "   → Delete it manually or run the task before re-creating." -ForegroundColor DarkYellow
    return
  }

  if (-not (Test-Path $baseFolder)) {
    New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null
  }

  Copy-Item -Path $absolutePath -Destination $msiDest -Force

  $scriptContent = @"
`$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Output "[👽] `$ts - Starting silent WSL MSI install..." | Out-File -FilePath "`$env:TEMP\WinPostInstall.log" -Append

Start-Process msiexec.exe -ArgumentList '/i `"$msiDest`" /quiet /norestart' -Wait

Write-Output "[✔️] `$ts - Installed: $msiDest" | Out-File -FilePath "`$env:TEMP\WinPostInstall.log" -Append

schtasks /Delete /TN "$taskName" /F | Out-Null
Remove-Item -Force "$psScriptPath"
"@

  # $scriptContent | Out-File -FilePath $psScriptPath -Encoding utf8BOM -Force
  [System.IO.File]::WriteAllText($psScriptPath, $scriptContent, [System.Text.UTF8Encoding]::new($true))

  $action = "powershell.exe -ExecutionPolicy Bypass -File `"$psScriptPath`""
  schtasks /Create /TN "$taskName" /TR "$action" /SC ONSTART /RL HIGHEST /F | Out-Null

  Write-Host ""
  Write-Host "[👽] $ts - MSI scheduled to install on next boot:" -ForegroundColor Cyan
  Write-Host "   → $msiDest" -ForegroundColor Green
  Write-Host "   → Task name: $taskName" -ForegroundColor DarkGray
  Write-Host "   → Script: $psScriptPath" -ForegroundColor DarkGray
}


<#
.SYNOPSIS
Enables WSL and related features, then installs Debian, Ubuntu, and Kali Linux.

.DESCRIPTION
Checks if required features (WSL and Virtual Machine Platform) are enabled, enables them if necessary,
updates WSL to version 2, and installs Debian, Ubuntu, and Kali Linux distributions.

.OUTPUTS
None. Provides console output indicating the status with alien emojis [👽], success [✔️], and error [💀].
#>
function Enable-WSLAndInstallDistros {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
  Write-Host "[👽] $ts - Checking and enabling required WSL features..." -ForegroundColor Cyan
  Write-Host ""

  $requiredFeatures = @(
    "Microsoft-Windows-Subsystem-Linux",
    "VirtualMachinePlatform"
  )

  foreach ($feature in $requiredFeatures) {
    $featureState = (Get-WindowsOptionalFeature -Online -FeatureName $feature).State
    if ($featureState -ne "Enabled") {
      Write-Host "[👽] $ts - Enabling feature: $feature" -ForegroundColor Cyan
      try {
        dism.exe /Online /Enable-Feature /FeatureName:$feature /All /NoRestart | Out-Null
        Write-Host "[✔️] $ts - Successfully enabled: $feature." -ForegroundColor Green
      }
      catch {
        Write-Host "[💀] $ts - Failed to enable feature: $feature. Error: $_" -ForegroundColor Red
      }
    }
    else {
      Write-Host "[✔️] $ts - Feature already enabled: $feature" -ForegroundColor Green
    }
  }

  Write-Host "[👽] $ts - Updating WSL kernel (via wsl --update)..." -ForegroundColor Cyan
  wsl --update

  Write-Host "[👽] $ts - Installing latest WSL kernel MSI..." -ForegroundColor Cyan
  Install-MSI -MSIPaths ".\src\softwares\wsl_update_x64.msi"

  Write-Host "[👽] $ts - Preparing to install WSL distros (Debian, Ubuntu, Kali)..." -ForegroundColor Cyan
  $distros = @("Debian", "Ubuntu", "kali-linux")

  foreach ($distro in $distros) {
    Write-Host "[👽] $ts - Installing distro: $distro" -ForegroundColor Cyan
    try {
      wsl --install -d $distro
      Write-Host "[✔️] $ts - Successfully initiated installation for $distro." -ForegroundColor Green
    }
    catch {
      Write-Host "[💀] $ts - Failed to install distro: $distro. Error: $_" -ForegroundColor Red
    }
  }

  Write-Host "[👽] $ts - Setting WSL default version to 2..." -ForegroundColor Cyan
  wsl --set-default-version 2

  Write-Host "[👽] $ts - WSL configuration completed. A reboot is recommended." -ForegroundColor Yellow
}


function Register-WSLAndInstallDistrosOnBoot {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $baseFolder  = "C:\WinPostInstall\WSL"
  $psScriptPath = Join-Path $baseFolder "InstallWSL.ps1"
  $taskName   = "WinPostInstall_WSLSetup"

  $taskExists = schtasks /Query /TN $taskName /FO LIST /ErrorAction SilentlyContinue 2>$null
  if ($taskExists) {
    Write-Host "[⚠️] $ts - Scheduled task '$taskName' already exists. Aborting." -ForegroundColor Yellow
    return
  }

  if (-not (Test-Path $baseFolder)) {
    New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null
  }

  if (Test-Path $psScriptPath) {
    Write-Host "[⚠️] $ts - Script already exists: $psScriptPath" -ForegroundColor Yellow
    Write-Host "   → Delete or rename it before re-creating." -ForegroundColor DarkYellow
    return
  }

  $scriptContent = @"
`$ts = Get-Date -Format 'M/d/yyyy h:mm:ss tt'
Write-Host "[👽] `$ts - Enabling WSL, installing distros..." -ForegroundColor Cyan
Wrote-Host ""

`$requiredFeatures = @(
  "Microsoft-Windows-Subsystem-Linux",
  "VirtualMachinePlatform"
)
foreach (`$feature in `$requiredFeatures) {
  `$state = (Get-WindowsOptionalFeature -Online -FeatureName `$feature).State
  if (`$state -ne "Enabled") {
    Write-Host "[👽] `$ts - Enabling feature: `$feature" -ForegroundColor Cyan
    dism.exe /Online /Enable-Feature /FeatureName:`$feature /All /NoRestart | Out-Null
    Write-Host "[✔️] `$ts - Enabled: `$feature." -ForegroundColor Green
  } else {
    Write-Host "[✔️] `$ts - Already enabled: `$feature" -ForegroundColor Green
  }
}

Write-Host "[👽] `$ts - Updating WSL kernel..." -ForegroundColor Cyan
wsl --update

Write-Host "[👽] `$ts - Installing WSL kernel MSI from .\src\softwares\wsl_update_x64.msi" -ForegroundColor Cyan
Install-MSI -MSIPaths ".\src\softwares\wsl_update_x64.msi"

`$distros = @("Debian", "Ubuntu", "kali-linux")
foreach (`$distro in `$distros) {
  Write-Host "[👽] `$ts - Installing \`$distro" -ForegroundColor Cyan
  wsl --install -d `$distro
  Write-Host "[✔️] `$ts - Distros initiated: `$distro" -ForegroundColor Green
}

Write-Host "[👽] `$ts - Setting WSL default to version 2" -ForegroundColor Cyan
wsl --set-default-version 2

Write-Host "[✔️] `$ts - WSL configuration done. Reboot if needed." -ForegroundColor Green

schtasks /Delete /TN "$taskName" /F | Out-Null
Remove-Item -Force "$psScriptPath"
"@

  [System.IO.File]::WriteAllText($psScriptPath, $scriptContent, [System.Text.UTF8Encoding]::new($true))

  $action = "powershell.exe -ExecutionPolicy Bypass -File `"$psScriptPath`""
  schtasks /Create /TN "$taskName" /TR "$action" /SC ONSTART /RL HIGHEST /F | Out-Null

  Write-Host ""
  Write-Host "[👽] $ts - WSL setup scheduled for next boot." -ForegroundColor Cyan
  Write-Host "   → Task name: $taskName" -ForegroundColor Green
  Write-Host "   → Script: $psScriptPath" -ForegroundColor DarkGray
}


function Wait-ForInstallWSLRemoval {
  param(
    [int]$TimeoutSeconds = 300 # 5 minutes
  )

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $scriptPath = "C:\WinPostInstall\WSL\InstallWSL.ps1"
  $startTime = Get-Date
  $endTime  = $startTime.AddSeconds($TimeoutSeconds)

  Write-Host "[👽] $ts - Waiting for $scriptPath to be removed..."

  while ((Get-Date) -lt $endTime) {
    if (-not (Test-Path $scriptPath)) {
      $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
      Write-Host "[✔️] $ts - $scriptPath was removed. WSL setup presumably done." -ForegroundColor Green
      return
    }
    Start-Sleep -Seconds 5
  }

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[⚠️] $ts - Timed out after $TimeoutSeconds seconds. $scriptPath still exists." -ForegroundColor Yellow
}


function Restart-System {
  <#
  .SYNOPSIS
  Restarts the system, optionally forcing a reboot.

  .DESCRIPTION
  Logs an alien-style message, then restarts the computer.
  If -Force is specified, forces an immediate reboot (closing apps without prompt).

  .PARAMETER Force
  When specified, forces an immediate restart (equivalent to Restart-Computer -Force).

  .EXAMPLE
  Restart-System

  .EXAMPLE
  Restart-System -Force
  #>
  [CmdletBinding()]
  param(
    [switch]$Force
  )

  $ts = Get-Date -Format "M/d/yyyy h:mm:ss tt"
  Write-Host "[👽] $ts - Initiating system reboot..." -ForegroundColor Yellow
  Write-Host ""

  try {
    if ($Force) {
      Write-Host "[👽] $ts - Force parameter detected. Closing apps without prompt..." -ForegroundColor Red
      Restart-Computer -Force
    }
    else {
      Restart-Computer
    }
  }
  catch {
    Write-Host "[💀] $ts - Failed to reboot system. Error: $_" -ForegroundColor Red
  }
}


<#
.SYNOPSIS
Sets Windows to treat the hardware clock as UTC, then resyncs time.

.DESCRIPTION
- Writes the RealTimeIsUniversal registry entry to store the hardware clock in UTC.
- Starts Windows Time service if not already started.
- Forces a time resynchronization with w32tm /resync.

Requires Administrator privileges to modify HKLM keys.

.EXAMPLE
Set-ClockToUTCTime
#>
function Set-ClockToUTCTime {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Setting clock to UTC time..." -ForegroundColor Cyan
  Write-Host ""
  try {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" `
      -Name "RealTimeIsUniversal" `
      -Type DWord `
      -Value 1 -Force | Out-Null
    
    # Start Windows Time service if not running
    $timeService = Get-Service "W32Time" -ErrorAction SilentlyContinue
    if ($timeService.Status -ne "Running") {
      net start "W32Time" | Out-Null
      Write-Host "[👽] $ts - Windows Time service started." -ForegroundColor Cyan
    }
    else {
      Write-Host "[👽] $ts - Windows Time service already running." -ForegroundColor Green
    }

    # Force time sync
    w32tm /resync | Out-Null

    Write-Host "[✔️] $ts - Clock successfully set to UTC and time resynced." -ForegroundColor Green
  }
  catch {
    Write-Host "[💀] $ts - Failed to set clock to UTC: $_" -ForegroundColor Red
  }
}


<#
.SYNOPSIS
Disables Windows Fast Startup.

.DESCRIPTION
Sets the HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power\HiberbootEnabled value to 0,
disabling Fast Startup. Requires Administrator privileges.
#>
function Disable-FastStartup {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Disabling Fast Startup..." -ForegroundColor Cyan
  Write-Host ""

  try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" `
             -Name "HiberbootEnabled" `
             -Type DWord `
             -Value 0 -Force

    Write-Host "[✔️] $ts - Fast Startup disabled." -ForegroundColor Green
  }
  catch {
    Write-Host "[💀] $ts - Failed to disable Fast Startup. Error: $_" -ForegroundColor Red
  }
}

<#
.SYNOPSIS
Shows known file extensions.

.DESCRIPTION
Sets HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt to 0,
which makes file extensions visible in Explorer.
#>
function Show-KnownExtensions {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Showing known file extensions..." -ForegroundColor Cyan
  Write-Host ""

  try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
             -Name "HideFileExt" `
             -Type DWord `
             -Value 0 -Force

    Write-Host "[✔️] $ts - File extensions are now visible." -ForegroundColor Green
  }
  catch {
    Write-Host "[💀] $ts - Failed to show file extensions. Error: $_" -ForegroundColor Red
  }
}

<#
.SYNOPSIS
Shows hidden files in Explorer.

.DESCRIPTION
Sets HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden to 1,
which makes hidden files visible.
#>
function Show-HiddenFiles {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Showing hidden files..." -ForegroundColor Cyan
  Write-Host ""

  try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
             -Name "Hidden" `
             -Type DWord `
             -Value 1 -Force

    Write-Host "[✔️] $ts - Hidden files are now visible." -ForegroundColor Green
  }
  catch {
    Write-Host "[💀] $ts - Failed to show hidden files. Error: $_" -ForegroundColor Red
  }
}

<#
.SYNOPSIS
Disables recent files in Explorer Quick Access.

.DESCRIPTION
Sets HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShowRecent to 0,
hiding recent files in Explorer Quick Access.
#>
function Disable-RecentFiles {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Disabling recent files in Explorer..." -ForegroundColor Cyan
  Write-Host ""

  try {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
             -Name "ShowRecent" `
             -Type DWord `
             -Value 0 -Force

    Write-Host "[✔️] $ts - Recent files disabled." -ForegroundColor Green
  }
  catch {
    Write-Host "[💀] $ts - Failed to disable recent files. Error: $_" -ForegroundColor Red
  }
}


<#
.SYNOPSIS
Disables frequent files in Explorer Quick Access.

.DESCRIPTION
Sets HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShowFrequent to 0,
so that "Frequent Folders" no longer appear in Quick Access.
#>
function Disable-FrequentFiles {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Disabling frequent files in Explorer..." -ForegroundColor Cyan
  Write-Host ""
  try {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
             -Name "ShowFrequent" `
             -Type DWord `
             -Value 0 -Force

    Write-Host "[✔️] $ts - Frequent files disabled." -ForegroundColor Green
  }
  catch {
    Write-Host "[💀] $ts - Failed to disable frequent files: $_" -ForegroundColor Red
  }
}


<#
.SYNOPSIS
Shows super hidden system files in Explorer.

.DESCRIPTION
Sets HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden to 1,
making system-protected hidden files/folders visible.
#>
function Show-SuperHiddenFiles {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Showing super hidden system files..." -ForegroundColor Cyan
  Write-Host ""
  try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
             -Name "ShowSuperHidden" `
             -Type DWord `
             -Value 1 -Force

    Write-Host "[✔️] $ts - Super hidden files are now visible." -ForegroundColor Green
  }
  catch {
    Write-Host "[💀] $ts - Failed to show super hidden files: $_" -ForegroundColor Red
  }
}


<#
.SYNOPSIS
Enables "God Mode" on the Desktop.

.DESCRIPTION
Creates a special folder named "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
on the Desktop, allowing easy access to advanced settings.
#>
function Enable-GodMode {
  [CmdletBinding()]
  param()

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $GodModePath = "$HOME\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"

  if (Test-Path -Path $GodModePath) {
    Write-Host "[✔️] $ts - God Mode shortcut already exists on Desktop." -ForegroundColor Green
  }
  else {
    Write-Host "[👽] $ts - Creating God Mode shortcut on Desktop..." -ForegroundColor Cyan
    Write-Host ""
    try {
      New-Item -Path "$HOME\Desktop" `
           -Name "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" `
           -ItemType "Directory" -ErrorAction Stop | Out-Null

      Write-Host "[✔️] $ts - God Mode shortcut created successfully!" -ForegroundColor Green
    }
    catch {
      Write-Host "[💀] $ts - Failed to create God Mode shortcut: $_" -ForegroundColor Red
    }
  }
}


function Remove-BloatwarePackages {
<#
.SYNOPSIS
Uninstalls preinstalled UWP apps (bloatware) from the system.

.DESCRIPTION
Iterates through a list of known unwanted Appx packages and provisioned packages,
attempting to remove each one while providing color-coded, timestamped, alien-themed feedback.

.Requires
Administrator privileges for removing provisioned packages (HKLM context).

.PARAMETER AppsList
An array of strings indicating the package names or wildcards to remove. 
Defaults to a predefined set if not provided.

.EXAMPLE
Remove-BloatwarePackages

.EXAMPLE
Remove-BloatwarePackages -AppsList @("Microsoft.ZuneMusic", "Microsoft.ZuneVideo")
#>
  [CmdletBinding()]
  param(
    [Parameter()]
    [string[]]$AppsList = @(
      "Microsoft.GetHelp","Microsoft.People","Microsoft.YourPhone","Microsoft.GetStarted",
      "Microsoft.Messaging","Microsoft.MicrosoftSolitaireCollection","Microsoft.ZuneMusic",
      "Microsoft.ZuneVideo","Microsoft.Office.OneNote","Microsoft.OneConnect","Microsoft.SkypeApp",
      "Microsoft.CommsPhone","Microsoft.Office.Sway","Microsoft.WindowsFeedbackHub",
      "Microsoft.ConnectivityStore","Microsoft.BingFoodAndDrink","Microsoft.BingHealthAndFitness",
      "Microsoft.BingTravel","Microsoft.WindowsReadingList","DB6EA5DB.MediaSuiteEssentialsforDell",
      "DB6EA5DB.Power2GoforDell","DB6EA5DB.PowerDirectorforDell","DB6EA5DB.PowerMediaPlayerforDell",
      "DellInc.DellDigitalDelivery","*Disney*","*EclipseManager*","*ActiproSoftwareLLC*",
      "*AdobeSystemsIncorporated.AdobePhotoshopExpress*","*Duolingo-LearnLanguagesforFree*",
      "*PandoraMediaInc*","*CandyCrush*","*BubbleWitch3Saga*","*Wunderlist*","*Flipboard*",
      "*Royal Revolt*","*Sway*","*Speed Test*","46928bounde.EclipseManager",
      "613EBCEA.PolarrPhotoEditorAcademicEdition","7EE7776C.LinkedInforWindows",
      "89006A2E.AutodeskSketchBook","ActiproSoftwareLLC.562882FEEB491","CAF9E577.Plex",
      "ClearChannelRadioDigital.iHeartRadio","Drawboard.DrawboardPDF","Fitbit.FitbitCoach",
      "Flipboard.Flipboard","KeeperSecurityInc.Keeper","Microsoft.BingNews",
      "TheNewYorkTimes.NYTCrossword","WinZipComputing.WinZipUniversal","A278AB0D.MarchofEmpires",
      "6Wunderkinder.Wunderlist","A278AB0D.DisneyMagicKingdoms","2FE3CB00.PicsArt-PhotoStudio",
      "D52A8D61.FarmVille2CountryEscape","D5EA27B7.Duolingo-LearnLanguagesforFree",
      "DB6EA5DB.CyberLinkMediaSuiteEssentials","GAMELOFTSA.Asphalt8Airborne",
      "NORDCURRENT.COOKINGFEVER","PandoraMediaInc.29680B314EFC2","Playtika.CaesarsSlotsFreeCasino",
      "ShazamEntertainmentLtd.Shazam","ThumbmunkeysLtd.PhototasticCollage","TuneIn.TuneInRadio",
      "XINGAG.XING","flaregamesGmbH.RoyalRevolt2","king.com.*","king.com.BubbleWitch3Saga",
      "king.com.CandyCrushSaga","king.com.CandyCrushSodaSaga"
    )
  )

  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[👽] $ts - Initiating interstellar purge of Windows bloatware..." -ForegroundColor Cyan
  Write-Host ""

  foreach ($App in $AppsList) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $PackageFullName = (Get-AppxPackage -Name $App -ErrorAction SilentlyContinue).PackageFullName
    $ProPackageFullName = (Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $App }).PackageName

    if ($PackageFullName) {
      Write-Host "[👽] $ts - Removing installed bloatware package: $App" -ForegroundColor Cyan
      try {
        Remove-AppxPackage -Package $PackageFullName -ErrorAction Stop | Out-Null
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[✔️] $ts - Package '$App' removed from user profile." -ForegroundColor Green
      }
      catch {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[💀] $ts - Failed to remove '$App': $_" -ForegroundColor Red
      }
    }
    else {
      Write-Host "[👻] $ts - Installed package not found: $App" -ForegroundColor Yellow
    }

    if ($ProPackageFullName) {
      Write-Host "[👽] $ts - Removing provisioned bloatware: $ProPackageFullName" -ForegroundColor Cyan
      try {
        Remove-AppxProvisionedPackage -Online -PackageName $ProPackageFullName -ErrorAction Stop | Out-Null
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[✔️] $ts - Provisioned package '$ProPackageFullName' removed." -ForegroundColor Green
      }
      catch {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[💀] $ts - Failed to remove provisioned '$ProPackageFullName': $_" -ForegroundColor Red
      }
    }
    else {
      Write-Host "[👻] $ts - No provisioned package found for: $App" -ForegroundColor Yellow
    }

    Start-Sleep -Milliseconds 200
  }

$messages = @(
  "[👽] ...We removed Candy Crush, but we can't remove the NSA's daily crush on your data.",
  "[👽] ...We removed Candy Crush, but we can't remove the NSA's daily crush on your data.",
  "[👽] ...We removed Candy Crush, but we can't remove the NSA's daily crush on your data.",

  "[🔍] ...Windows itself might be the biggest bloat, but let's not talk about that.",
  "[🔍] ...Windows itself might be the biggest bloat, but let's not talk about that.",
  "[🔍] ...Windows itself might be the biggest bloat, but let's not talk about that.",

  "[🫣] ...We've abducted bloatware. Sorry, not the DGSI though. They're still watching.",
  "[🫣] ...We've abducted bloatware. Sorry, not the DGSI though. They're still watching.",
  "[🫣] ...We've abducted bloatware. Sorry, not the DGSI though. They're still watching.",

  "[🛰️] ...If only the DGSI’s code was as easy to remove as Candy Crush. 👋",
  "[🛰️] ...If only the DGSI’s code was as easy to remove as Candy Crush. 👋",

  "[💡] ...We tried to remove Windows itself, but apparently it’s essential to your PC. Who knew?",
  "[💡] ...We tried to remove Windows itself, but apparently it’s essential to your PC. Who knew?",

  "[🤡] ...Your PC is lighter now – ironically, the heaviest part remains Windows itself.",
  "[🕵️] ...At least we zapped these apps. The Windows telemetry? Still in orbit."
)

	Write-Host ""
	$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	Write-Host "[👽] $ts - Galactic bloatware purge complete." -ForegroundColor Green
	Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Copy-Wallpapers {
<#
.SYNOPSIS
Copies all files (recursively) from SourcePath to DestinationPath, handling collisions. Also copies a main wallpaper to FinalCopyPath.

.DESCRIPTION
Checks or creates $DestinationPath.
Lists all files in $SourcePath and its subfolders (Recurse).
Copies each file to the corresponding subfolder in $DestinationPath with -ConflictAction logic.
If $MainWallpaper is found in $DestinationPath, copies it to $FinalCopyPath with the same collision logic.

.PARAMETER SourcePath
Path to your wallpapers (files + subfolders).

.PARAMETER DestinationPath
Where to put the copied structure of files.

.PARAMETER MainWallpaper
A special filename to also copy to $FinalCopyPath if found in DestinationPath.

.PARAMETER FinalCopyPath
Where to place the main wallpaper if found in DestinationPath.

.PARAMETER ConflictAction
"Overwrite": overwrites collisions,
"Skip": does nothing if the file already exists,
"Prompt": asks you Y/N at each collision.

.EXAMPLE
Copy-Wallpapers

.EXAMPLE
Copy-Wallpapers -SourcePath ".\src\images\wallpapers" -DestinationPath "C:\Wallpapers" -ConflictAction Prompt
#>
    [CmdletBinding()]
    param(
        [string]$SourcePath       = ".\src\images\wallpapers",
        [string]$DestinationPath  = "C:\Wallpapers",
        [string]$MainWallpaper    = "wallpaper.png",
        [string]$FinalCopyPath    = "C:\wallpaper.png",
        [ValidateSet("Overwrite","Skip","Prompt")]
        [string]$ConflictAction   = "Overwrite"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Copying wallpapers (recursively) from '$SourcePath' to '$DestinationPath' (Collision=$ConflictAction)..." -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-Path $SourcePath)) {
        Write-Host "[💀] $ts - Source path '$SourcePath' does not exist. Aborting." -ForegroundColor Red
        return
    }

    if (-not (Test-Path $DestinationPath)) {
        try {
            New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
            Write-Host "[👽] $ts - Created destination folder: $DestinationPath" -ForegroundColor Cyan
        }
        catch {
            Write-Host "[💀] $ts - Failed to create destination folder '$DestinationPath': $_" -ForegroundColor Red
            return
        }
    }

    $fileList = Get-ChildItem -Path $SourcePath -Recurse -File
    if (-not $fileList) {
        Write-Host "[🫣] $ts - No files found in '$SourcePath'. Nothing to copy." -ForegroundColor Yellow
    }
    else {
        foreach ($file in $fileList) {
            $sourceResolved = (Resolve-Path $SourcePath).Path  # version absolue
            $relativePath   = $file.FullName.Substring($sourceResolved.Length)
            # On vire les backslashes ou slashes initiaux
            $relativePath   = $relativePath.TrimStart('\','/')

            $destFullPath   = Join-Path $DestinationPath $relativePath

            $destDir = Split-Path $destFullPath -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }

            $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            if (Test-Path $destFullPath) {
                # Collision
                switch ($ConflictAction) {
                    "Overwrite" {
                        Copy-Item -Path $file.FullName -Destination $destFullPath -Force
                        Write-Host "[✔️] $ts - Overwrote existing file: $relativePath" -ForegroundColor Green
                    }
                    "Skip" {
                        Write-Host "[🫣] $ts - Skipped existing file: $relativePath" -ForegroundColor Yellow
                    }
                    "Prompt" {
                        $answer = Read-Host "[?] $ts - File '$relativePath' exists. Overwrite? (Y/N)"
                        if ($answer -match "^[Yy]") {
                            Copy-Item -Path $file.FullName -Destination $destFullPath -Force
                            Write-Host "[✔️] $ts - Overwrote '$relativePath' upon confirmation." -ForegroundColor Green
                        }
                        else {
                            Write-Host "[🫣] $ts - Skipped '$relativePath' upon user request." -ForegroundColor Yellow
                        }
                    }
                }
            }
            else {
                Copy-Item -Path $file.FullName -Destination $destFullPath -Force
                Write-Host "[✔️] $ts - Copied new file: $relativePath" -ForegroundColor Green
            }
        }
    }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $mainSource = Join-Path $DestinationPath $MainWallpaper
    if (Test-Path $mainSource) {
        if (Test-Path $FinalCopyPath) {
            switch ($ConflictAction) {
                "Overwrite" {
                    Copy-Item -Force $mainSource $FinalCopyPath
                    Write-Host "[✔️] $ts - Main wallpaper '$MainWallpaper' overwritten at '$FinalCopyPath'." -ForegroundColor Green
                }
                "Skip" {
                    Write-Host "[🫣] $ts - Skipped overwriting main wallpaper '$FinalCopyPath' (already exists)." -ForegroundColor Yellow
                }
                "Prompt" {
                    $answer = Read-Host "[?] $ts - '$FinalCopyPath' exists. Overwrite main wallpaper? (Y/N)"
                    if ($answer -match "^[Yy]") {
                        Copy-Item -Force $mainSource $FinalCopyPath
                        Write-Host "[✔️] $ts - Main wallpaper overwritten at '$FinalCopyPath'." -ForegroundColor Green
                    }
                    else {
                        Write-Host "[🫣] $ts - Skipped main wallpaper at '$FinalCopyPath' on user request." -ForegroundColor Yellow
                    }
                }
            }
        }
        else {
            Copy-Item -Force $mainSource $FinalCopyPath
            Write-Host "[✔️] $ts - Main wallpaper '$MainWallpaper' copied to '$FinalCopyPath'." -ForegroundColor Green
        }
    }
    else {
        Write-Host "[🫣] $ts - Main wallpaper '$MainWallpaper' not found in '$DestinationPath'." -ForegroundColor Yellow
    }

    $messages = @(
        "[👽] ...Now the NSA can admire your fresh wallpapers too.",
        "[👽] ...If only the DGSI’s scanning tools were as pretty as your new background.",
        "[👽] ...At least the watchers will see your brand-new wallpaper in full HD.",
        "[👽] ...Your desktop is stylin', but the DGSI still sees everything."
    )

	Write-Host ""
	$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	Write-Host "[👽] $ts - Wallpaper copy process (recursive) completed. ConflictAction=$ConflictAction." -ForegroundColor Green
	Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Set-DesktopWallpaperFromImage {
<#
.SYNOPSIS
Sets the desktop wallpaper from an existing image file, forcing Windows to refresh.

.DESCRIPTION
Check that the image exists.
Update the HKCU:\Control PanelDesktop\WallpaperStyle + TileWallpaper key (e.g. Fill).
Updates "Wallpaper" key.
Call SystemParametersInfo(SPI_SETDESKWALLPAPER) with SPIF_UPDATEINIFILE+SPIF_SENDWININICHANGE.

.PARAMETER ImagePath
Full path to an existing wallpaper image (PNG, JPG, BMP...).

.PARAMETER WallpaperStyle
Possible values: "Centered","Tiled","Stretched","Fit","Fill" (Windows 7+).
Defaults to "Fill".

.EXAMPLE
Set-DesktopWallpaperFromImage -ImagePath "C:\MyWall.png" -WallpaperStyle "Centered"
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ImagePath,

        [ValidateSet("Centered","Tiled","Stretched","Fit","Fill")]
        [string]$WallpaperStyle = "Fill"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Setting desktop wallpaper to image: '$ImagePath' (Style=$WallpaperStyle)..." -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-Path $ImagePath)) {
        Write-Host "[💀] $ts - File not found: $ImagePath. Aborting." -ForegroundColor Red
        return
    }

    # TileWallpaper=0/1, WallpaperStyle=0/2/6/10
    switch ($WallpaperStyle) {
        "Centered"  { $tile = 0; $style = 0 }
        "Tiled"     { $tile = 1; $style = 0 }
        "Stretched" { $tile = 0; $style = 2 }
        "Fit"       { $tile = 0; $style = 6 }
        "Fill"      { $tile = 0; $style = 10 }
    }

    try {
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "TileWallpaper" -Value $tile
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WallpaperStyle" -Value $style
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value $ImagePath
    }
    catch {
        Write-Host "[💀] $ts - Failed to set registry for wallpaper style: $_" -ForegroundColor Red
        return
    }

    Add-Type -MemberDefinition @"
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto, SetLastError=true)]
    public static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
"@ -Name "NativeMethods" -Namespace "PInvoke"

    # SPI_SETDESKWALLPAPER = 20
    # SPIF_UPDATEINIFILE = 0x1, SPIF_SENDWININICHANGE = 0x2
    $SPI_SETDESKWALLPAPER = 20
    $SPIF_UPDATEINIFILE   = 0x1
    $SPIF_SENDWININICHANGE= 0x2

    # 4) Force la maj du bureau
    $ret = [PInvoke.NativeMethods]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $ImagePath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDWININICHANGE)
    if ($ret -eq 0) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "[💀] $ts - SystemParametersInfo failed. Error code: $err" -ForegroundColor Red
    }
    else {
        Write-Host "[✔️] $ts - Wallpaper successfully changed to '$ImagePath'." -ForegroundColor Green
    }
}


function Set-DesktopWallpaperFromColor {
<#
.SYNOPSIS
Generates a 1x1 BMP in the chosen color and sets it as the desktop wallpaper.

.DESCRIPTION
- Uses System.Drawing to create a 1x1 pixel image of the chosen color.
- Saves it to $env:TEMP\solidcolor.bmp (by default).
- Updates registry keys to force Windows to re-apply the wallpaper style.
- Calls SystemParametersInfo(SPI_SETDESKWALLPAPER) to guarantee immediate refresh.

.PARAMETER ColorName
Color name or hex (e.g. "Black", "Red", "FF00FF", "0,128,255"). Defaults to Black.

.PARAMETER OutFile
Where to save the generated BMP. Defaults to "$env:TEMP\solidcolor.bmp".

.PARAMETER WallpaperStyle
Possible values: "Centered", "Tiled", "Stretched", "Fit", "Fill". Default "Fill".

.EXAMPLE
Set-DesktopWallpaperFromColor -ColorName "Blue"
.EXAMPLE
Set-DesktopWallpaperFromColor -ColorName "#FF0000" -WallpaperStyle "Centered"
#>

    [CmdletBinding()]
    param(
        [string]$ColorName = "Black",
        [string]$OutFile = "$env:TEMP\solidcolor.bmp",
        [ValidateSet("Centered","Tiled","Stretched","Fit","Fill")]
        [string]$WallpaperStyle = "Fill"
    )

    Add-Type -AssemblyName System.Drawing
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Creating a 1x1 BMP of color '$ColorName'..." -ForegroundColor Cyan
    Write-Host ""

    $colorObj = $null
    try {
        $colorObj = [System.Drawing.Color]::FromName($ColorName)
        if ($colorObj.IsKnownColor -eq $false) {
            if ($ColorName -match "^#?([A-Fa-f0-9]{6})$") {
                $r = [Convert]::ToByte($Matches[1].Substring(0,2),16)
                $g = [Convert]::ToByte($Matches[1].Substring(2,2),16)
                $b = [Convert]::ToByte($Matches[1].Substring(4,2),16)
                $colorObj = [System.Drawing.Color]::FromArgb($r,$g,$b)
            }
            elseif ($ColorName -match "^\d{1,3},\d{1,3},\d{1,3}$") {
                $parts = $ColorName.Split(",")
                $r = [int]$parts[0]
                $g = [int]$parts[1]
                $b = [int]$parts[2]
                $colorObj = [System.Drawing.Color]::FromArgb($r,$g,$b)
            }
            else {
                Write-Host "[🫣] $ts - Unrecognized color format '$ColorName'. Using Black." -ForegroundColor Yellow
                $colorObj = [System.Drawing.Color]::Black
            }
        }
    }
    catch {
        Write-Host "[🫣] $ts - Error parsing color '$ColorName'. Using Black." -ForegroundColor Yellow
        $colorObj = [System.Drawing.Color]::Black
    }

    try {
        $bmp = New-Object System.Drawing.Bitmap(1,1)
        $bmp.SetPixel(0, 0, $colorObj)

        $bmp.Save($OutFile, [System.Drawing.Imaging.ImageFormat]::Bmp)
        $bmp.Dispose()

        Write-Host "[✔️] $ts - Generated BMP '$OutFile' in color '$ColorName'." -ForegroundColor Green
    }
    catch {
        Write-Host "[💀] $ts - Failed to create BMP: $_" -ForegroundColor Red
        return
    }

    # Convertir WallpaperStyle en codes
    switch ($WallpaperStyle) {
        "Centered"  { $tile = 0; $style = 0 }
        "Tiled"     { $tile = 1; $style = 0 }
        "Stretched" { $tile = 0; $style = 2 }
        "Fit"       { $tile = 0; $style = 6 }
        "Fill"      { $tile = 0; $style = 10 }
    }
    try {
        # HKCU:\Control Panel\Desktop
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "TileWallpaper" -Value $tile
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WallpaperStyle" -Value $style
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value $OutFile
    }
    catch {
        Write-Host "[💀] $ts - Failed to set registry for wallpaper style: $_" -ForegroundColor Red
        return
    }

    Add-Type -MemberDefinition @"
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto, SetLastError=true)]
    public static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
"@ -Name "NativeMethods" -Namespace "PInvoke"

    # SPI_SETDESKWALLPAPER = 20
    # SPIF_UPDATEINIFILE = 0x1, SPIF_SENDWININICHANGE = 0x2
    $SPI_SETDESKWALLPAPER = 20
    $SPIF_UPDATEINIFILE = 0x1
    $SPIF_SENDWININICHANGE = 0x2

    $result = [PInvoke.NativeMethods]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $OutFile, $SPIF_UPDATEINIFILE -bor $SPIF_SENDWININICHANGE)

    if ($result -eq 0) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "[💀] $ts - SystemParametersInfo failed. Error code: $err" -ForegroundColor Red
    }
    else {
    	Write-Host ""
        Write-Host "[✔️] $ts - Desktop wallpaper successfully updated to solid color: $ColorName." -ForegroundColor Green
    }
}


function Install-Executables {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ExecutableNames,

        [string]$SourcePath = ".\src\softwares",

        [switch]$Silent
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Beginning executable installations..." -ForegroundColor Cyan
    Write-Host ""

    foreach ($exeName in $ExecutableNames) {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $exePath = Join-Path -Path $SourcePath -ChildPath $exeName

        Write-Host "[👽] $ts - Preparing to install: $exeName" -ForegroundColor Cyan

        if (-Not (Test-Path -Path $exePath)) {
            Write-Host "[💀] $ts - File not found: '$exePath'" -ForegroundColor Red
            continue
        }

        try {
            if ($Silent) {
                Start-Process -FilePath $exePath -ArgumentList "/s" -WindowStyle Hidden -ErrorAction Stop
            } else {
                Start-Process -FilePath $exePath -WindowStyle Hidden -ErrorAction Stop
            }

            Write-Host "[✔️] $ts - Installation started: $exeName (waiting 5s before next)" -ForegroundColor Green
            Start-Sleep -Seconds 5
        } catch {
            Write-Host "[💀] $ts - Failed to start: $exeName. Error: $_" -ForegroundColor Red
        }
    }

    $messages = @(
        "[🔍] ...Another .exe? The NSA thanks you for your contribution.",
        "[🧠] ...That .exe just got 5 new threads. And 3 of them are *very* curious.",
        "[🛰️] ...Thanks for installing. Your signal is now clearer from orbit.",
        "[🧰] ...One tool installed. One more opportunity for someone to peek inside.",
        "[💉] ...Executable injected. Don’t worry, just a harmless installer. Probably."
    )

    Write-Host ""
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Executable installation loop completed." -ForegroundColor Green
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Install-eDEX {
    <#
    .SYNOPSIS
    Installs eDEX-UI based on system architecture (x64, x86, or ARM).

    .DESCRIPTION
    Detects the system architecture and installs the matching eDEX executable:
    - eDEX-UI-Windows-x64.exe for 64-bit
    - eDEX-UI-Windows.exe for 32-bit or ARM (via x86 emulation)

    .PARAMETER SourcePath
    Path to the folder where the installers are stored. Default: .\src\softwares\eDEX-UI-Windows
    #>

    [CmdletBinding()]
    param (
        [string]$SourcePath = ".\src\softwares\eDEX-UI-Windows"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Starting eDEX-UI installation..." -ForegroundColor Cyan
    Write-Host ""

    try {
        $arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    } catch {
        Write-Host "[💀] $ts - Failed to detect OS architecture. Aborting." -ForegroundColor Red
        return
    }

    switch -Wildcard ($arch) {
        "*64*" {
            $exeName = "eDEX-UI-Windows-x64.exe"
        }
        "*32*" {
            $exeName = "eDEX-UI-Windows.exe"
        }
        "*ARM*" {
            Write-Host "[🧬] $ts - ARM architecture detected. Falling back to x86 installer (emulated)." -ForegroundColor Yellow
            $exeName = "eDEX-UI-Windows.exe"
        }
        default {
            Write-Host "[🫣] $ts - Unknown architecture: '$arch'. Aborting install." -ForegroundColor Yellow
            return
        }
    }

    $exePath = Join-Path -Path $SourcePath -ChildPath $exeName

    if (-Not (Test-Path -Path $exePath)) {
        Write-Host "[💀] $ts - Installer not found: '$exePath'" -ForegroundColor Red
        return
    }

    Write-Host "[👽] $ts - Detected architecture: $arch" -ForegroundColor Cyan
    Write-Host "[👽] $ts - Selected installer: $exeName" -ForegroundColor Cyan

    try {
        Start-Process -FilePath $exePath -ErrorAction Stop
        Write-Host "[✔️] $ts - eDEX-UI installation started. Waiting 5s before continuing..." -ForegroundColor Green
        Start-Sleep -Seconds 5
    } catch {
        Write-Host "[💀] $ts - Failed to start eDEX-UI install. Error: $_" -ForegroundColor Red
    }

    $messages = @(
        "[🧠] ...eDEX installed. You now have a terminal cooler than your actual job.",
        "[🛰️] ...Interface activated. The NSA thanks you for the visual upgrade."
    )

    Write-Host ""
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Extract-ZipArchives {
    <#
    .SYNOPSIS
    Extracts one or more ZIP archives to a specified destination folder.

    .DESCRIPTION
    Extracts each .zip to a folder matching its name. Handles nested folders (e.g. double folders like \Foo\Foo\).
    Supports conflict handling via -ConflictAction:
    - Overwrite: deletes and re-extracts
    - Skip: skips if folder already exists
    - Prompt: asks before extracting

    .PARAMETER ZipPaths
    One or more paths to .zip files.

    .PARAMETER DestinationPath
    The folder where contents will be extracted (parent). Defaults to folder containing zip.

    .PARAMETER ConflictAction
    Overwrite | Skip | Prompt (default: Overwrite)

    .EXAMPLE
    Extract-ZipArchives -ZipPaths ".\archive.zip" -ConflictAction Prompt
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ZipPaths,

        [string]$DestinationPath,

        [ValidateSet("Overwrite", "Skip", "Prompt")]
        [string]$ConflictAction = "Overwrite"
    )

    foreach ($zipPath in $ZipPaths) {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        if (-not (Test-Path $zipPath)) {
            Write-Host "[💀] $ts - File not found: $zipPath" -ForegroundColor Red
            continue
        }

        $zipLeaf  = Split-Path $zipPath -Leaf
        $zipName  = [System.IO.Path]::GetFileNameWithoutExtension($zipLeaf)
        $zipDir   = $DestinationPath
        if (-not $zipDir) { $zipDir = Split-Path $zipPath -Parent }

        $zipFolder = Join-Path $zipDir $zipName

        if (Test-Path $zipFolder) {
            switch ($ConflictAction) {
                "Skip" {
                    Write-Host "[🟡] $ts - Skipping extraction (already exists): $zipFolder" -ForegroundColor Yellow
                    continue
                }
                "Prompt" {
                    $answer = Read-Host "[?] $ts - '$zipFolder' exists. Overwrite? (Y/N)"
                    if ($answer -notmatch "^[Yy]") {
                        Write-Host "[🟡] $ts - User chose not to overwrite. Skipped: $zipFolder" -ForegroundColor Yellow
                        continue
                    }
                }
                "Overwrite" {
                    try {
                        Remove-Item -Path $zipFolder -Recurse -Force -ErrorAction Stop
                        Write-Host "[🧹] $ts - Removed existing folder: $zipFolder" -ForegroundColor DarkYellow
                    } catch {
                        Write-Host "[💀] $ts - Failed to delete existing folder '$zipFolder': $_" -ForegroundColor Red
                        continue
                    }
                }
            }
        }

        Write-Host "[👽] $ts - Extracting '$zipPath' to '$zipFolder'..." -ForegroundColor Cyan
        try {
            Expand-Archive -Path $zipPath -DestinationPath $zipFolder -Force
            Write-Host "[✔️] $ts - Extraction completed: $zipPath" -ForegroundColor Green
        } catch {
            Write-Host "[💀] $ts - Failed to extract '$zipPath'. Error: $_" -ForegroundColor Red
            continue
        }

        $nested = Join-Path $zipFolder $zipName
        # if (Test-Path $nested -and (Get-ChildItem $nested -Force | Measure-Object).Count -gt 0) {
        if ((Test-Path $nested) -and ((Get-ChildItem $nested -Force | Measure-Object).Count -gt 0)) {
            Write-Host "[🧠] $ts - Nested folder detected: '$nested'. Flattening structure..." -ForegroundColor Yellow
            Get-ChildItem -Path $nested -Force | ForEach-Object {
                Move-Item -Path $_.FullName -Destination $zipFolder -Force
            }
            Remove-Item -Path $nested -Recurse -Force
        }
    }

    $final = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "[👽] $final - All ZIP extractions finished." -ForegroundColor Green
}


function Install-DaVinciResolve {
    <#
    .SYNOPSIS
    Detects architecture, extracts the correct DaVinci Resolve ZIP, and installs the executable.

    .DESCRIPTION
    Uses Extract-ZipArchives and Install-Executables to fully automate DaVinci Resolve install.

    .NOTES
    ZIPs should be named:
        - DaVinci_Resolve_19.1.4_Windows.zip
        - DaVinci_Resolve_19.1.4_Windows_ARM64.zip

    .EXAMPLE
    Install-DaVinciResolve
    #>

    [CmdletBinding()]
    param ()

    $baseDir = ".\src\softwares\DaVinci_Resolve\DaVinci_Resolve_19.1.4_Windows"
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Starting DaVinci Resolve installation..." -ForegroundColor Cyan
    Write-Host ""

    try {
        $arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    } catch {
        Write-Host "[💀] $ts - Unable to detect OS architecture. Aborting." -ForegroundColor Red
        return
    }

    if ($arch -like "*ARM*") {
        $zip = Join-Path $baseDir "DaVinci_Resolve_19.1.4_Windows_ARM64.zip"
    } else {
        $zip = Join-Path $baseDir "DaVinci_Resolve_19.1.4_Windows.zip"
    }

    if (-not (Test-Path $zip)) {
        Write-Host "[💀] $ts - ZIP not found: $zip" -ForegroundColor Red
        return
    }

    Write-Host "[👽] $ts - Detected architecture: $arch" -ForegroundColor Cyan
    Write-Host "[👽] $ts - Selected archive: $zip" -ForegroundColor Cyan

    Extract-ZipArchives -ZipPaths $zip -ConflictAction "Overwrite"

	$zipLeaf = Split-Path $zip -Leaf
	$zipName = [System.IO.Path]::GetFileNameWithoutExtension($zipLeaf)
	$extractedPath = Join-Path (Split-Path $zip -Parent) $zipName

    $exe = Get-ChildItem -Path $extractedPath -Filter *.exe -Recurse -File | Select-Object -First 1
    if (-not $exe) {
        Write-Host "[💀] $ts - No .exe found in extracted folder: $extractedPath" -ForegroundColor Red
        return
    }

    Install-Executables -ExecutableNames $exe.Name -SourcePath $exe.DirectoryName
}


function Set-NumLockDefaultState {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Setting default Num Lock state..." -ForegroundColor Cyan
    Write-Host ""

    try {
        Set-ItemProperty -Path 'Registry::HKU\.DEFAULT\Control Panel\Keyboard' -Name "InitialKeyboardIndicators" -Value "2" -Force
        Write-Host "[✔️] $ts - Num Lock will be ON at next startup." -ForegroundColor Green
    } catch {
        Write-Host "[💀] $ts - Failed to set Num Lock state: $_" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "[👽] $ts - Num Lock configuration complete." -ForegroundColor Cyan
}


function Optimize-PerformanceSettings {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Optimizing visual effects for performance..." -ForegroundColor Cyan
    Write-Host ""

    try {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name "VisualFXSetting" -Type DWORD -Value 2 -Force
        Write-Host "[✔️] $ts - Visual effects set to 'Best Performance'." -ForegroundColor Green
    } catch {
        Write-Host "[💀] $ts - Failed to apply performance optimization: $_" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "[👽] $ts - Performance tweaks complete." -ForegroundColor Cyan
}


function Refresh-GroupPolicyAndWSUS {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Initiating Group Policy and Windows Update refresh..." -ForegroundColor Green
    Write-Host ""

    try {
        Write-Host "[🧠] $ts - Forcing Group Policy update..." -ForegroundColor Cyan
        gpupdate /force | Out-Null

        $date = Get-Date -Format "yyyyMMdd_HHmm"
        $reportPath = "C:\gpresult-$date.html"
        gpresult /H $reportPath | Out-Null

        Write-Host "[✔️] $ts - Group Policy refreshed. Report: $reportPath" -ForegroundColor Green
    } catch {
        Write-Host "[💀] $ts - Failed to refresh Group Policy: $_" -ForegroundColor Red
    }

    Write-Host ""
    try {
        Write-Host "[📡] $ts - Triggering Windows Update detection..." -ForegroundColor Cyan
        Start-Process -FilePath "wuauclt.exe" -ArgumentList "/detectnow" -NoNewWindow
        Write-Host "[✔️] $ts - Windows Update detection command sent." -ForegroundColor Green
    } catch {
        Write-Host "[💀] $ts - Failed to run Windows Update detection: $_" -ForegroundColor Red
    }

$messages = @(
    "[🧱] ...You just forced a policy. Somewhere, a sysadmin weeps.",
    "[🧾] ...Group Policy is enforced. Your freedom is conditional.",
    "[☁️] ...Update triggered. Somewhere in Redmond, a server blinked."
)

    Write-Host ""
    Write-Host "[👽] $ts - Group Policy and WSUS refresh complete." -ForegroundColor Cyan
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Pin-App {
    <#
    .SYNOPSIS
    Pins or unpins an application to the Start menu and/or Taskbar.

    .DESCRIPTION
    This function is intended to handle pinning and unpinning of applications using either their name or path.
    You can specify whether to target the Start menu, the Taskbar, or both.
    Functionality to be implemented.

    .PARAMETER AppName
    Name of the application as seen in the Start menu (e.g., "Microsoft Edge").

    .PARAMETER Path
    Full path to the executable or shortcut (e.g., "C:\Tools\MyApp.exe").

    .PARAMETER Start
    Indicates that the action should apply to the Start menu.

    .PARAMETER Taskbar
    Indicates that the action should apply to the Taskbar.

    .PARAMETER Unpin
    If set, the action will be to unpin instead of pinning.

    .EXAMPLE
    Pin-App -AppName "Microsoft Edge" -Start

    .EXAMPLE
    Pin-App -Path "C:\MyApp.exe" -Taskbar -Unpin

    .EXAMPLE
    Pin-App -AppName "C:" -Start

    .NOTES
    TODO: Implement logic using Shell.Application COM object or modern StartLayout/Taskbar policy/verb binding.

    #>

    [CmdletBinding()]
    param (
        [string]$AppName,
        [string]$Path,
        [switch]$Start,
        [switch]$Taskbar,
        [switch]$Unpin
    )

    # TODO: Implement logic to handle pinning/unpinning by AppName or Path.
    #       Use COM Shell.Application or future supported API if available.
    #       Consider edge cases for missing verbs, permissions, or already pinned items.
    #       Graceful fallbacks if not found.

    Write-Warning "Pin-App: Function not implemented yet. This is just a placeholder."
}


function Pin-ToStartMenu {
    <#
    .SYNOPSIS
    Pins one or more folders or drives to the Start menu.

    .DESCRIPTION
    Uses Shell.Application COM object to invoke the appropriate pin verb.
    - For drive roots (e.g. C:\), uses the 'PintoHome' verb.
    - For other folders, uses 'Pin to Start' context menu verb.
    
    No reliable detection of already pinned state - this toggles the pin state.

    .PARAMETER TargetPaths
    One or more paths to pin to the Start menu.

    .EXAMPLE
    Pin-ToStartMenu -TargetPaths "C:\", "$env:USERPROFILE\Documents", "D:\Tools"

    .NOTES
    This function does not detect if an item is already pinned.
    If already pinned, this may unpin it due to toggle behavior.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$TargetPaths
    )

    foreach ($TargetPath in $TargetPaths) {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[👽] $ts - Attempting to pin '$TargetPath' to Start menu..." -ForegroundColor Cyan
        Write-Host ""

        if (-not (Test-Path $TargetPath)) {
            Write-Host "[💀] $ts - Path not found: '$TargetPath'" -ForegroundColor Red
            continue
        }

        try {
            $shell = New-Object -ComObject Shell.Application

            if ($TargetPath -match '^[A-Z]:\\$') {
                # Root drive like C:\ — use PintoHome
                $folder = $shell.Namespace($TargetPath)
                $item   = $folder.Self
                $item.InvokeVerb("PintoHome")
                Write-Host "[✔️] $ts - Triggered pin action on drive: '$TargetPath'" -ForegroundColor Green
            }
            else {
                $parentPath = Split-Path $TargetPath -Parent
                $leaf       = Split-Path $TargetPath -Leaf
                $folder     = $shell.Namespace($parentPath)
                $item       = $folder.ParseName($leaf)

                $verb = $item.Verbs() | Where-Object { $_.Name -match "Pin to Start" }

                if ($verb) {
                    $verb.DoIt()
                    Write-Host "[✔️] $ts - Triggered pin action on folder: '$TargetPath'" -ForegroundColor Green
                }
                else {
                    Write-Host "[🫥] $ts - 'Pin to Start' not available for: '$TargetPath'" -ForegroundColor DarkYellow
                }
            }
        }
        catch {
            Write-Host "[💀] $ts - Failed to pin '$TargetPath'. Error: $_" -ForegroundColor Red
        }

    }
}


function Disable-UnnecessaryServices {
    <#
    .SYNOPSIS
    Disables a list of unnecessary or privacy-intrusive Windows services.

    .DESCRIPTION
    Disables services commonly considered useless or invasive, like telemetry, Xbox junk, 
    or diagnostics collectors. Helps reclaim RAM, privacy, and soul fragments stolen by Microsoft 👁️.

    .PARAMETER ServiceList
    Custom list of service names to disable. If not specified, uses the default anti-NSA preset.

    .EXAMPLE
    Disable-UnnecessaryServices
    Disable-UnnecessaryServices -ServiceList @("DiagTrack", "RemoteRegistry")
    #>

    [CmdletBinding()]
    param (
        [string[]]$ServiceList = @(
            # 🧠 Core services
            "WerSvc",                         # Windows Error Reporting
            "OneSyncSvc",                     # Sync Host
            "PcaSvc",                         # Program Compatibility Assistant
            "MessagingService",               # Messaging
            "RetailDemo",                     # Retail Demo
            "diagnosticshub.standardcollector.service", # Diagnostics Hub
            "lfsvc",                          # Geolocation Service
            "AJRouter",                       # AllJoyn Router
            "RemoteRegistry",                 # Remote Registry
            "DUSMsvc",                        # Data Usage
            "DiagTrack",                      # Telemetry 👁️
            "MapsBroker",                     # Downloaded Maps Manager

            # 🎮 Xbox-related
            "XblAuthManager",
            "XblGameSave",
            "XboxNetApiSvc",
            "XboxGipSvc"
        )
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Beginning service deactivation ritual..." -ForegroundColor Cyan
    Write-Host ""

    foreach ($svc in $ServiceList) {
        try {
            Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
            Write-Host "[☠️] $ts - Disabled service: $svc" -ForegroundColor Green
        } catch {
            Write-Host "[💀] $ts - Could not disable $svc. Error: $_" -ForegroundColor Red
        }
    }

  $messages = @(
      "[📡] ...NSA report: subject’s telemetry just went dark. Deploy drones?",
      "[🕵️‍♂️] ...RemoteRegistry deactivated. DGSI says 'suspicious behaviour'..",
      "[🚫] ...Microsoft: 'That’s not recommended.' User: 'That’s why I’m doing it.'"
  )

    Write-Host ""
    Write-Host "[👽] $ts - Mission complete. The OS is slightly less creepy now." -ForegroundColor Cyan
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Disable-UnwantedScheduledTasks {
    <#
    .SYNOPSIS
    Disables a list of scheduled tasks deemed unnecessary or intrusive.

    .DESCRIPTION
    Uses `schtasks.exe` to disable telemetry tasks, Xbox, CEIP, SmartScreen, etc.
    Allows you to regain some privacy, RAM and dignity.

    .PARAMETER TaskList
    Customized list of tasks to be disabled. By default, an anti-Windows-curiosity cocktail is used.

    .EXAMPLE
    Disable-UnwantedScheduledTasks
    Disable-UnwantedScheduledTasks -TaskList @("Microsoft\Windows\Application Experience\ProgramDataUpdater")
    #>

    [CmdletBinding()]
    param (
        [string[]]$TaskList = @(
            # 🔮 User experiences, telemetry, etc.
            "Microsoft\Windows\AppID\SmartScreenSpecific",
            "Microsoft\Windows\Application Experience\AitAgent",
            "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "Microsoft\Windows\Application Experience\StartupAppTask",
            "Microsoft\Windows\Autochk\Proxy",
            "Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
            "Microsoft\Windows\Customer Experience Improvement Program\BthSQM",
            "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
            "Microsoft\Windows\Customer Experience Improvement Program\Uploader",
            "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "Microsoft\Windows\Maintenance\WinSAT",
            "Microsoft\Windows\PI\Sqm-Tasks",

            # 👶 Family Safety and phantom parental controls
            "Microsoft\Windows\Shell\FamilySafetyMonitor",
            "Microsoft\Windows\Shell\FamilySafetyRefresh",
            "Microsoft\Windows\Shell\FamilySafetyUpload",
            "Microsoft\Windows\Shell\FamilySafetyMonitorToastTask",
            "Microsoft\Windows\Shell\FamilySafetyRefreshTask",

            # 📦 App update & Microsoft Maps
            "Microsoft\Windows\WindowsUpdate\Automatic App Update",
            "Microsoft\Windows\NetTrace\GatherNetworkInfo",
            "Microsoft\Windows\Maps\MapsUpdateTask",
            "Microsoft\Windows\Maps\MapsToastTask",

            # 🎮 Xbox GameSave
            "Microsoft\XblGameSave\XblGameSaveTask",
            "Microsoft\XblGameSave\XblGameSaveTaskLogon"
        )
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Beginning scheduled task deactivation..." -ForegroundColor Cyan
    Write-Host ""

    foreach ($task in $TaskList) {
        try {
            schtasks /Change /TN "$task" /Disable | Out-Null
            Write-Host "[☠️] $ts - Disabled task: $task" -ForegroundColor Green
        } catch {
            Write-Host "[💀] $ts - Could not disable task: $task. Error: $_" -ForegroundColor Red
        }
    }

    $messages = @(
        "[🛰️] ...Task disabled. Somewhere, a telemetry bot sheds a tear.",
        "[🎮] ...Xbox integration neutralized. Achievement unlocked: 🧠 Privacy +1.",
        "[🔕] ...FamilySafety task disabled. Your Windows no longer reports to your mom."
    )

    Write-Host ""
    Write-Host "[👽] $ts - Task neutralization complete." -ForegroundColor Cyan
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Apply-PerformanceAndPrivacyTweaks {
    <#
    .SYNOPSIS
    Applies performance, gaming and privacy tweaks to Windows.

    .DESCRIPTION
    - Disable Fullscreen Optimization for better performance and fewer graphics bugs.
    - Disable NetBIOS over TCP/IP (who lives there anymore??).
    - Disable Bing search in Start menu.
    
    .OUTPUTS
    Console stylisée avec des messages alien-friendly.
    #>

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Applying performance & privacy tweaks..." -ForegroundColor Cyan
    Write-Host ""

    # --- Disable Fullscreen Optimization ---
    try {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKU:\*\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKU:\*\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKU:\*\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Value 2 -ErrorAction SilentlyContinue
        Remove-PSDrive -Name HKU -Force -ErrorAction SilentlyContinue
        Write-Host "[🕹️] Fullscreen Optimization nuked. Games might stop flickering in 3... 2... 1..." -ForegroundColor Green
    } catch {
        Write-Host "[💀] Failed to disable Fullscreen Optimization: $_" -ForegroundColor Red
    }

    # --- Disable NetBIOS over TCP/IP ---
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT" -Name "Start" -Value 4 -Force
        Write-Host "[📵] NetBIOS disabled. No more 90s LAN ghosts haunting your packets." -ForegroundColor Green
    } catch {
        Write-Host "[💀] Failed to disable NetBIOS: $_" -ForegroundColor Red
    }

    # --- Disable Bing Search in Start Menu ---
    try {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord
        Write-Host "[🔒] Bing in Start Menu? Gone." -ForegroundColor Green
    } catch {
        Write-Host "[💀] Failed to disable web search suggestions: $_" -ForegroundColor Red
    }

    $end = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $messages = @(
        "[🧠] ...Windows tried to fight back. But it was too slow.",
        "[👁️] ...Congratulations. You have angered both Satya Nadella and Cortana."
    )

    Write-Host ""
    Write-Host "[👽] $end - Tweaks applied successfully." -ForegroundColor Cyan
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Optimize-NTFSSettings {
    <#
    .SYNOPSIS
    Applies NTFS and filesystem performance optimizations.

    .DESCRIPTION
    Configures NTFS behavior using `fsutil`:
    - Enables client-optimized memory usage for file system caching.
    - Disables last access timestamp updates for faster disk I/O.
    - Reserves more space for the Master File Table (MFT) to reduce fragmentation.

    Also attempts to shrink NTFS transaction logs on all mounted volumes.

    .NOTES
    Requires administrator privileges.
    #>

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Starting NTFS optimization..." -ForegroundColor Cyan
    Write-Host ""

    try {
        Write-Host "[📁] Setting NTFS memory usage to 1 (server-optimized)..." -ForegroundColor Cyan
        fsutil behavior set memoryusage 2 | Out-Null

        # Enables server-optimized file system caching (Mode 2).
        # NTFS memory usage modes:
        #    0 = Default (legacy behavior)
        #    1 = Client-optimized (balanced for UI responsiveness)
        #    2 = Server-optimized (aggressive caching, favors throughput)
        # 
        # This setting boosts performance on systems doing heavy file I/O:
        #    - large file transfers
        #    - Docker / WSL / VM workloads
        #    - development involving frequent read/write operations
        #
        # In short: Use 2 if you value throughput over UI snappiness.

        Write-Host "[🧠] Disabling LastAccess timestamp updates..." -ForegroundColor Cyan
        fsutil behavior set disablelastaccess 1 | Out-Null

        # Disables LastAccess timestamp updates on NTFS files.
        # NTFS normally updates the "last accessed" metadata every time a file or folder is opened,
        #    which causes unnecessary disk writes and hurts performance, especially on SSDs.
        #
        # fsutil behavior set disablelastaccess 1
        #    0 = Enable timestamp updates (default on older systems)
        #    1 = Disable updates for performance (recommended)
        #
        # Greatly improves file system performance on systems with:
        #    - lots of small file operations
        #    - development tools (compilers, git, WSL, Docker)
        #    - SSD/NVMe drives (limits write wear)

        Write-Host "[🧱] Setting MFT zone reservation to level 2 (25%)..." -ForegroundColor Cyan
        fsutil behavior set mftzone 2 | Out-Null

        # Configures the reserved size of the MFT (Master File Table) zone on NTFS volumes.
        # The MFT is the internal NTFS database that tracks all files on disk.
        #     If it becomes fragmented due to insufficient space, performance drops significantly.
        #
        # fsutil behavior set mftzone X
        #    X = 0 to 4 (corresponds to approx. 12.5%, 25%, 37.5%, 50% of volume reserved for MFT)
        #    0 = Default (12.5%)
        #    1 = 12.5%   — conservative (default)
        #    2 = 25%     — recommended for systems with LOTS of files (dev envs, containers, git, etc.)
        #    3 = 37.5%
        #    4 = 50%     — only if you’re running a massive number of small files (e.g., mail servers)

        Write-Host ""
        Write-Host "[📂] Shrinking NTFS transaction logs on mounted volumes..." -ForegroundColor Cyan

        $volumes = Get-CimInstance Win32_Volume | Where-Object { $_.DriveLetter -and $_.FileSystem -eq "NTFS" }

        foreach ($vol in $volumes) {
            $drive = $vol.DriveLetter
            try {
                Write-Host "[🧪] Processing volume $drive..." -ForegroundColor Green
                fsutil resource setavailable "$drive\" | Out-Null
                fsutil resource setlog shrink 10 "$drive\" | Out-Null
            } catch {
                Write-Host "[💀] Failed to optimize $drive. Error: $_" -ForegroundColor Red
            }
        }

        Write-Host ""
        Write-Host "[✔️] $ts - NTFS optimizations completed successfully." -ForegroundColor Green
    } catch {
        Write-Host "[💀] $ts - NTFS optimization failed: $_" -ForegroundColor Red
    }
}


function Enable-VirtualizationSecurityFeatures {
    <#
    .SYNOPSIS
    Enables virtualization-based Windows security features for enhanced isolation.

    .DESCRIPTION
    Activates the following features:
    - Virtualization-Based Security (VBS)
    - Credential Guard
    - Hypervisor-Enforced Code Integrity (HVCI)

    These features leverage hardware virtualization to isolate sensitive processes,
    credentials, and kernel-mode memory integrity from tampering.

    .NOTES
    Requires a reboot to take full effect.
    May cause compatibility issues with unsigned drivers or legacy software.

    .EXAMPLE
    Enable-VirtualizationSecurityFeatures
    #>

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Activating virtualization-based security features..." -ForegroundColor Cyan
    Write-Host ""

    try {
        # 🛡️ Enable VBS
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
                         -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
        Write-Host "[🛡️] VBS enabled." -ForegroundColor Green

        # 🔐 Enable Credential Guard
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" `
                         -Name "Enabled" -Value 1 -Type DWord
        Write-Host "[🔐] Credential Guard enabled." -ForegroundColor Green

        # 📦 Enable HVCI (Memory Integrity)
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
                         -Name "Enabled" -Value 1 -Type DWord
        Write-Host "[📦] HVCI (Memory Integrity) enabled." -ForegroundColor Green

        Write-Host ""
        Write-Host "[☠️] $ts - All features enabled. A reboot is required for changes to take effect." -ForegroundColor Cyan

        $messages = @(
            "[🤖] VBS enabled. Windows now runs in a tiny hypervisor bubble, like a nerd in a tinfoil hat.",
            "[🧠] Your system now refuses to trust itself. You're welcome."
        )
        Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow

    }
    catch {
        Write-Host "[💀] $ts - Failed to enable virtualization-based security. Error: $_" -ForegroundColor Red
    }
}


function Disable-ContentDeliveryManager {
    <#
    .SYNOPSIS
    Disables all Windows Content Delivery features, ads, preinstalled app spam, and UI suggestions.

    .DESCRIPTION
    Removes intrusive registry values from all users (HKU) under ContentDeliveryManager,
    including SubscribedContent telemetry keys. Disables most lock screen ads, tips, Microsoft suggestions, and preinstalled junk.

    .NOTES
    Microsoft Marketing may attempt retaliation. You’ve been warned.
    #>

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Initiating Content Delivery Manager purge ritual..." -ForegroundColor Cyan
    Write-Host ""

    try {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

        # Get all real user hives (skip default/system hives)
        $userHives = Get-ChildItem -Path "HKU:\" | Where-Object { $_.Name -notmatch '(^S-1-5-18|^S-1-5-19|^S-1-5-20|_Classes$)' }

        foreach ($hive in $userHives) {
            $basePath = Join-Path $hive.PSPath "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

            if (Test-Path $basePath) {
                Write-Host "[🧪] Cleaning hive: $($hive.Name)" -ForegroundColor DarkCyan

                # Try to remove subkeys
                Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue |
                ForEach-Object {
                    try {
                        Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    } catch {}
                }

                # Remove SubscribedContent-*Enabled props
                Get-ItemProperty -Path $basePath -ErrorAction SilentlyContinue |
                Get-Member -MemberType NoteProperty |
                Where-Object { $_.Name -like "SubscribedContent-*Enabled" } |
                ForEach-Object {
                    try {
                        Remove-ItemProperty -Path $basePath -Name $_.Name -ErrorAction SilentlyContinue
                    } catch {}
                }

                # Disable hardcoded list of keys
                $keys = @(
                    "ContentDeliveryAllowed",
                    "FeatureManagementEnabled",
                    "OemPreInstalledAppsEnabled",
                    "PreInstalledAppsEnabled",
                    "PreInstalledAppsEverEnabled",
                    "RotatingLockScreenEnabled",
                    "RotatingLockScreenOverlayEnabled",
                    "SlideshowEnabled",
                    "SilentInstalledAppsEnabled",
                    "SoftLandingEnabled",
                    "SystemPaneSuggestionsEnabled"
                )

                foreach ($key in $keys) {
                    try {
                        Set-ItemProperty -Path $basePath -Name $key -Value 0 -Force -ErrorAction SilentlyContinue
                        Write-Host "[👽] Disabled '$key' in hive: $($hive.Name)" -ForegroundColor Green
                    } catch {}
                }
            }
        }

        Write-Host ""
        Write-Host "[👽] $ts - All Content Delivery features eliminated across users. Ad-free serenity achieved." -ForegroundColor Cyan

        $messages = @(
            "[🕵️‍♂️] DGSI just lost telemetry on your lock screen. Suspicion level: elevated.",
            "[📺] Microsoft Ads Team: 'Sir, we’ve lost another user. They're escaping the influence.'"
        )
        Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
    }
    catch {
        Write-Host "[💀] $ts - Failed to purge Content Delivery Manager: $_" -ForegroundColor Red
    }

    Remove-PSDrive -Name "HKU" -Force -ErrorAction SilentlyContinue
}


function Enable-WindowsDefenderAdvancedProtection {
    <#
    .SYNOPSIS
    Applies a complete hardening suite for Microsoft Defender and Windows security mechanisms.

    .DESCRIPTION
    This function configures:
    - Windows Defender Exploit Protection via XML policy (e.g. DOD_EP_V3.xml)
    - WDAC policy (Recommended_Audit) using ConvertFrom-CIPolicy + RefreshPolicy.exe (per arch)
    - Full customization of Defender preferences using Get/Set-MpPreference
    - ASR (Attack Surface Reduction) rules to block known TTPs like LOLBins, macro abuse, etc.
    - Cloud protection & MAPS settings
    - Signature updates (background)
    - Full system scan (background)
    - Logs system status & outputs flavor text with cyber-alien humor

    .NOTES
    Files must be present in `.src\etc\WD\Files\Windows Defender Configuration Files`
    Requires elevation.
    WDAC policy requires reboot to fully apply (depends on scenario).
    #>

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Enabling Windows Defender Protections and Features..." -ForegroundColor Cyan

    $sourcePath = ".\src\etc\WD\Files\Windows Defender Configuration Files"
    $exploitProtectionXml = Join-Path $sourcePath "DOD_EP_V3.xml"
    $wdacDir  = Join-Path $sourcePath "WDAC"
    $wdacXml = Join-Path $wdacDir "WDAC_V1_Recommended_Audit.xml"
    $wdacCip = Join-Path $env:TEMP "WDAC_V1_Recommended_Audit.cip"

    # Exploit Guard Policy
    if (Test-Path $exploitProtectionXml) {
        try {
            Write-Host "[🧠] Applying Exploit Protection policy..." -ForegroundColor Yellow
            Set-ProcessMitigation -PolicyFilePath $exploitProtectionXml
        } catch {
            Write-Host "[💀] Failed to apply Exploit Protection policy: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "[❌] Missing file: $exploitProtectionXml" -ForegroundColor DarkRed
    }

    # WDAC Conversion + Refresh
    try {
        Write-Host "[🧬] Converting WDAC XML policy to CIP..." -ForegroundColor Yellow
        if (-not (Test-Path $wdacXml)) {
            Write-Host "[💀] WDAC XML policy not found: $wdacXml" -ForegroundColor Red
            return
        }
        ConvertFrom-CIPolicy -XmlFilePath $wdacXml -BinaryFilePath $wdacCip -ErrorAction Stop
        $targetFolder = "$env:windir\System32\CodeIntegrity\CIPolicies\Active"
        Copy-Item -Path $wdacCip -Destination $targetFolder -Force

        $arch = $env:PROCESSOR_ARCHITECTURE
        switch ($arch) {
            "AMD64" { $refreshTool = Join-Path $wdacDir "RefreshPolicy(AMD64).exe" }
            "ARM64" { $refreshTool = Join-Path $wdacDir "RefreshPolicy(ARM64).exe" }
            "x86"   { $refreshTool = Join-Path $wdacDir "RefreshPolicy(X86).exe" }
            default {
                Write-Host "[💀] Unsupported architecture: $arch" -ForegroundColor Red
                return
            }
        }

        if (-not (Test-Path $refreshTool)) {
            Write-Host "[💀] RefreshPolicy binary not found: $refreshTool" -ForegroundColor Red
            return
        }

        Write-Host "[🔁] Refreshing WDAC policy with: $refreshTool" -ForegroundColor Yellow
        & $refreshTool
        Write-Host "[✅] WDAC policy successfully deployed: WDAC_V1_Recommended_Audit" -ForegroundColor Green
    }
    catch {
        Write-Host "[💀] Failed to apply WDAC policy: $_" -ForegroundColor Red
    }

    # Defender Configuration
    try {
        Write-Host ""
        Write-Host "[🛡️] Enabling and Setting Defender..." -ForegroundColor Yellow

        # https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSetting
        # https://social.technet.microsoft.com/wiki/contents/articles/52251.manage-windows-defender-using-powershell.aspx
        # https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps

        $mpPreference = Get-MpPreference
        $mpPreference.DisableRealtimeMonitoring = $false
        $mpPreference.MAPSReporting = "0"
        $mpPreference.SubmitSamplesConsent = "AlwaysPrompt"
        $mpPreference.CheckForSignaturesBeforeRunningScan = 1
        $mpPreference.DisableBehaviorMonitoring = $false
        $mpPreference.DisableIOAVProtection = $false
        $mpPreference.DisableScriptScanning = $false
        $mpPreference.DisableRemovableDriveScanning = $false
        $mpPreference.DisableBlockAtFirstSeen = $false
        $mpPreference.PUAProtection = 1
        $mpPreference.DisableArchiveScanning = $false
        $mpPreference.DisableEmailScanning = $false
        $mpPreference.EnableFileHashComputation = $true
        $mpPreference.DisableIntrusionPreventionSystem = $false
        $mpPreference.DisableSshParsing = $false
        $mpPreference.DisableDnsParsing = $false
        $mpPreference.DisableDnsOverTcpParsing = $false
        $mpPreference.EnableDnsSinkhole = $true
        $mpPreference.EnableControlledFolderAccess = "Enabled"
        $mpPreference.EnableNetworkProtection = "Enabled"
        $mpPreference.MP_FORCE_USE_SANDBOX = 1
        $mpPreference.CloudBlockLevel = "High"
        $mpPreference.CloudExtendedTimeout = 50
        $mpPreference.SignatureDisableUpdateOnStartupWithoutEngine = $false
        $mpPreference.DisableArchiveScanningAlternateDataStream = $false
        $mpPreference.DisableBehaviorMonitoringAlternateDataStream = $false
        $mpPreference.ScanArchiveFilesWithPassword = $true
        $mpPreference.ScanDownloads = 2
        $mpPreference.ScanNetworkFiles = 2
        $mpPreference.ScanIncomingMail = 2
        $mpPreference.ScanMappedNetworkDrivesDuringFullScan = $true
        $mpPreference.ScanRemovableDrivesDuringFullScan = $true
        $mpPreference.ScanScriptsLoadedInInternetExplorer = $true
        $mpPreference.ScanScriptsLoadedInOfficeApplications = $true
        $mpPreference.ScanSubDirectoriesDuringQuickScan = $true
        $mpPreference.ScanRemovableDrivesDuringQuickScan = $true
        $mpPreference.ScanMappedNetworkDrivesDuringQuickScan = $true
        $mpPreference.DisableBehaviorMonitoringMemoryDoubleFree = $false
        $mpPreference.DisableBehaviorMonitoringNonSystemSigned = $false
        $mpPreference.DisableBehaviorMonitoringUnsigned = $false
        $mpPreference.DisableBehaviorMonitoringPowershellScripts = $false
        $mpPreference.DisableBehaviorMonitoringNonMsSigned = $false
        $mpPreference.DisableBehaviorMonitoringNonMsSystem = $false
        $mpPreference.DisableBehaviorMonitoringNonMsSystemProtected = $false
        $mpPreference.EnableControlledFolderAccessMemoryProtection = $true
        $mpPreference.EnableControlledFolderAccessNonScriptableDlls = $true
        $mpPreference.EnableControlledFolderAccessNonMsSigned = $true
        $mpPreference.EnableControlledFolderAccessNonMsSystem = $true
        $mpPreference.EnableControlledFolderAccessNonMsSystemProtected = $true
        $mpPreference.ScanRemovableDriveDuringFullScan = $true
        $mpPreference.ScanNetworkFilesDuringFullScan = $true
        $mpPreference.ScanNetworkFilesDuringQuickScan = $true
        $mpPreference.EnableNetworkProtectionRealtimeInspection = $true
        $mpPreference.EnableNetworkProtectionExploitInspection = $true
        $mpPreference.EnableNetworkProtectionControlledFolderAccessInspection = $true
        $mpPreference.SignatureDisableUpdateOnStartupWithoutEngine = $false
        $mpPreference.SignatureDisableUpdateOnStartupWithoutEngine = $false
        
        Set-MpPreference -PreferenceObject $mpPreference

        Write-Host "[✅] Defender preferences set successfully." -ForegroundColor Green
    } catch {
        Write-Host "[💀] Failed to apply Defender preferences: $_" -ForegroundColor Red
    }

      Write-Host "[👽] Disabling Account Prompts" -ForegroundColor Cyan
      $accountProtectionKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State\AccountProtection_MicrosoftAccount_Disconnected"

      if (!(Test-Path -Path $accountProtectionKeyPath)) {
          New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType DWORD -Value 1 -Force
      } else {
          Set-ItemProperty -Path $accountProtectionKeyPath -Name "AccountProtection_MicrosoftAccount_Disconnected" -Value 1
      }

    Write-Host "[👽] Configure Cloud-delivered Protections" -ForegroundColor Cyan
    Set-MpPreference -MAPSReporting 0
    Set-MpPreference -SubmitSamplesConsent AlwaysPrompt

  Write-Host ""
  Write-Host "[👽] Enabling Windows Defender Attack Surface Reduction (ASR) Rules..." -ForegroundColor Cyan

  $asrRules = @{
      "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
      "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
      "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
      "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
      "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
      "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
      "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
      "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
      "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem"
      "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
      "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
      "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
      "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
      "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
      "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
      "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
      "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode (preview)"
      "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools (preview)"
      "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
  }

  $currentRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids

  foreach ($ruleId in $asrRules.Keys) {
      if ($currentRules -contains $ruleId) {
          Write-Host " [🟡] Already enabled: $($asrRules[$ruleId])" -ForegroundColor DarkYellow
      } else {
          Write-Host " [🛡️] Enabling: $($asrRules[$ruleId])" -ForegroundColor Cyan
          Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled
      }
  }

    $messages = @(
        "[🧬] T1059.001 disabled. PowerShell tried to obfuscate -Enc payload... got enc-ountered by ASR instead.",
        "[🧬] T1059.001 disabled. PowerShell tried to obfuscate -Enc payload... got enc-ountered by ASR instead.",
        "[🧬] T1059.001 disabled. PowerShell tried to obfuscate -Enc payload... got enc-ountered by ASR instead.",
        "[🧬] T1059.001 disabled. PowerShell tried to obfuscate -Enc payload... got enc-ountered by ASR instead.",
        "[🧬] T1059.001 disabled. PowerShell tried to obfuscate -Enc payload... got enc-ountered by ASR instead.",

        "[📡] SOC dashboard flatlined. Wazuh stopped alerting. Analysts now play Tetris.",
        "[📡] SOC dashboard flatlined. Wazuh stopped alerting. Analysts now play Tetris.",
        "[📡] SOC dashboard flatlined. Wazuh stopped alerting. Analysts now play Tetris.",

        "[🔍] 14 layers of Base64 and 2 rounds of XOR later… ASR said: 'Try obfuscating your career path instead.",
        "[🔍] 14 layers of Base64 and 2 rounds of XOR later… ASR said: 'Try obfuscating your career path instead.",
        "[🔍] 14 layers of Base64 and 2 rounds of XOR later… ASR said: 'Try obfuscating your career path instead.",

        "[📡] SOC dashboard flatlined. Wazuh stopped alerting. Analysts now play Tetris.",
        "[📨] Blocked executable payload in Outlook attachment. Sorry Emotet, phishing season is over.",
        "[📎] Office macro tried to spawn cmd.exe. Cobalt Strike didn’t even load its stage.",
        "[🕷️] Blocked obfuscated script from launching executable. No, wscript base64.ps1 is not normal.",
        "[📚] Office macro attempted API calls to VirtualAlloc. MITRE T1059.005 got body-slammed.",
        "[🧠] LSASS access attempt detected. Mimikatz sulked and closed itself.",
        "[📨] Adobe Reader launched cmd.exe. Not today, CVE-2018-4990.",
        "[☠️] Sysmon caught a hacker crying. He just wanted one unsigned driver."
    )

    Write-Host ""
    Write-Host "[👽] $ts - ASR hardening complete." -ForegroundColor Green
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow

    Write-Host ""
    Write-Host "[👽] Updating Signatures..." -ForegroundColor Cyan
    # Update-MpSignature -UpdateSource MicrosoftUpdateServer
    # Update-MpSignature -UpdateSource MMPC

#    try {
#        $status = Get-MpComputerStatus
#
#        if ($status.AntispywareSignatureUpdateInProgress -or $status.AntivirusSignatureUpdateInProgress) {
#            Write-Host "[🕒] Signature update already in progress. Skipping manual update." -ForegroundColor Yellow
#            return
#        }
#
#        Write-Host "[🌐] Initiating update from MicrosoftUpdateServer..." -ForegroundColor Gray
#        Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop
#
#        Write-Host "[🌐] Initiating update from MMPC..." -ForegroundColor Gray
#        Update-MpSignature -UpdateSource MMPC -ErrorAction Stop
#
#        Write-Host "[✅] Signatures updated successfully." -ForegroundColor Green
#    } catch {
#        Write-Host "[💀] Failed to update Defender signatures: $_" -ForegroundColor Red
#    }

    try {
        $status = Get-MpComputerStatus

        if ($status.AntispywareSignatureUpdateInProgress -or $status.AntivirusSignatureUpdateInProgress) {
            Write-Host "[🕒] Signature update already in progress. Skipping manual update." -ForegroundColor Yellow
        } else {
            Write-Host "[🌐] Starting signature update in background..." -ForegroundColor Cyan
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -Command Update-MpSignature -UpdateSource MicrosoftUpdateServer; Update-MpSignature -UpdateSource MMPC" -WindowStyle Hidden
            Write-Host "[✅] Signature update launched." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[💀] Signature update failed: $_" -ForegroundColor Red
    }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "[👁️‍🗨️] $ts - Dumping Defender system configuration..." -ForegroundColor Cyan
    Write-Host "[🧠] Retrieving: Computer Status, Preferences, Threat History & Detection Stats..." -ForegroundColor Gray

    # Diagnostic dump
    Get-MpComputerStatus
    Get-MpPreference
    Get-MpThreat
    Get-MpThreatDetection

    Write-Host ""
    # Write-Host "[👾] $ts - Initiating full system sweep..." -ForegroundColor Cyan
    # Write-Host "[🔍] Starting FullScan: Expect elevated CPU usage, disk IO spikes, and possible alien screeches." -ForegroundColor Yellow
    # Start-MpScan -ScanType FullScan

    Write-Host "[👾] $ts - Launching FullScan in background process..." -ForegroundColor Cyan
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -Command Start-MpScan -ScanType FullScan" -WindowStyle Hidden
    Write-Host "[🧬] FullScan initiated silently. Check Defender logs or Event Viewer for progress." -ForegroundColor Green

    Write-Host ""
    Write-Host "[⚔️] $ts - Engaging threat removal protocol..." -ForegroundColor Cyan
    Write-Host "[☣️] Quarantined payloads will be neuralized. No interplanetary appeal possible." -ForegroundColor Yellow
    Remove-MpThreat

    Write-Host ""
    Write-Host "[🧬] $ts - Scan cycle complete. Threats have been vaporized. Defender logs now taste like Splunk dashboards." -ForegroundColor Green

    $messages = @(
    "[🧾] Microsoft signed an NDA before scanning your machine.",
    "[🧾] Microsoft signed an NDA before scanning your machine.",
    "[🧾] Microsoft signed an NDA before scanning your machine.",
    "[🧾] Microsoft signed an NDA before scanning your machine.",

    "[🕵️‍♂️] DGSE tried lateral movement. They now think your machine is a honeypot deployed by Mossad.",
    "[🕵️‍♂️] DGSE tried lateral movement. They now think your machine is a honeypot deployed by Mossad.",
    "[🕵️‍♂️] DGSE tried lateral movement. They now think your machine is a honeypot deployed by Mossad.",
    "[🕵️‍♂️] DGSE tried lateral movement. They now think your machine is a honeypot deployed by Mossad.",

    "[🪖] Defender entered autonomous threat-neutralization mode. Your SOC analyst was replaced by AI and a Nerf gun.",
    "[🪖] Defender entered autonomous threat-neutralization mode. Your SOC analyst was replaced by AI and a Nerf gun.",
    "[🪖] Defender entered autonomous threat-neutralization mode. Your SOC analyst was replaced by AI and a Nerf gun.",

    "[📡] Defender now asks permission before breathing.",
    "[📡] Defender now asks permission before breathing.",
    "[📡] Defender now asks permission before breathing.",

    "[💬] Wazuh node status: 'Clean. Too clean. Suspiciously clean.'",
    "[💬] Wazuh node status: 'Clean. Too clean. Suspiciously clean.'",

    "[📣] FBI sent you a letter: ‘Stop blocking our beacon. Or we’ll write a blog post about you.’",
    "[📣] FBI sent you a letter: ‘Stop blocking our beacon. Or we’ll write a blog post about you.’",

    "[🧃] Your PC’s so hardened even Splunk started logging compliments.",
    "[🛡️] Defender is now more paranoid than your ex. Even calc.exe is being watched.",
    "[📉] Threat actors downgraded their TTPs: too much friction, not enough dopamine.",
    "[👁️] Defender entered kill mode. Sysinternals flagged you as overhardened."
    )

    Write-Host ""
    Write-Host "[👽] $ts - Alien-grade hardening complete." -ForegroundColor Cyan
    Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
}


function Execute-HardeningKitty {
    <#
    .SYNOPSIS
    Extracts, loads, and runs HardeningKitty from .\lib.

    .DESCRIPTION
    Automatically extracts HardeningKitty-master.zip into .\lib,
    then imports the module and runs Invoke-HardeningKitty with emoji support.

    .NOTES
    Requires Extract-ZipArchives to be defined.
    The .zip must be located at .\lib\HardeningKitty-master.zip.
    #>

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $zipPath = ".\lib\HardeningKitty-master.zip"
    $destFolder = ".\lib"
    $kittyRoot = Join-Path $destFolder "HardeningKitty-master"

    Write-Host "[👽] $ts - Installing HardeningKitty..." -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-Path $zipPath)) {
        Write-Host "[💀] $ts - ZIP archive not found: $zipPath" -ForegroundColor Red
        return
    }

    Extract-ZipArchives -ZipPaths $zipPath -DestinationPath $destFolder -ConflictAction "Overwrite"

    $moduleFile = Get-ChildItem -Path $kittyRoot -Recurse -Filter "HardeningKitty.psm1" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $moduleFile) {
        Write-Host "[💀] $ts - Module not found after extraction: HardeningKitty.psm1" -ForegroundColor Red
        return
    }
    $kittyModule = $moduleFile.FullName

    try {
        Import-Module $kittyModule -Force -ErrorAction Stop
        Write-Host "[📦] $ts - Module imported: HardeningKitty" -ForegroundColor Green

        Invoke-HardeningKitty -EmojiSupport -Mode Config

        $messages = @(
            "[🕵️‍♂️] DGSI pinged Microsoft... got a 403 and a polite 'ça ne marche plus, frère'.",
            "[👺] APT41 sent a ticket to Beijing: 'Target hardened, send ransomware elsewhere.'",
            "[🐱‍💻] APT41 tried 'Remote Desktop Guest Login' — got slapped by HardeningKitty and sent back to China.",
            "[🔒] Splunk dashboard reports: no more weird logons at 3AM. The intern is safe.",
            "[🧠] Wazuh dashboard is now silent. SOC team thought the sensors broke — turns out, you just hardened everything.",
            "[👀] Your Event ID 4624s are so tight, Red Teams dream about you in nightmares.",
            "[🌐] SMBv1: 'Just let me exist...' — Blocked. Forever.",
            "[🎮] Sorry kids, this system is now rated 'Military Grade'.",
            "[📡] Splunk detected zero anomalies. SIEM engineer fainted. Forensics confirmed: no IOC, just good hardening.",
            "[🪵] Sysmon logs so clean, even ElasticSearch took a break. Fileless malware gave up halfway.",
            "[👁️] NSA ran recon and left a note: 'You win this round, kitten lover.'",
            "[🕵️‍♂️] DGSE couldn’t enumerate your shares. Now they’re using pigeons again.",
            "[📬] GCHQ sent you a strongly worded email titled: 'How dare you block our telemetry beacon?'",
            "[🛰️] Five Eyes lost visibility on your machine. They’re now considering wet work.",
            "[📉] CISA removed you from the vulnerable systems list. That’s how real it got.",
            "[📜] Your audit policy is so complete, Edward Snowden bookmarked it as a bedtime story.",
            "[🚷] Your attack surface is smaller than a Raspberry Pi in a Faraday cage.",
            "[🔍] Your firewall blocked a TCP handshake. The packet left a Yelp review: 0/5, very rude."
        )
        Write-Host "[☠️] $ts - Hardening complete. This system now qualifies for entry into a secret Swiss bunker." -ForegroundColor Cyan
        Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
    }
    catch {
        Write-Host "[💀] $ts - Failed to run HardeningKitty: $_" -ForegroundColor Red
    }
}


function Audit-HardeningKitty {
    <#
    .SYNOPSIS
    Extracts, loads, and audits the system using HardeningKitty without making any changes.

    .DESCRIPTION
    Automatically extracts HardeningKitty-master.zip into .\lib,
    then imports the module and runs Invoke-HardeningKitty in Audit mode (read-only) with emoji support.

    .NOTES
    Requires Extract-ZipArchives to be defined.
    The .zip must be located at .\lib\HardeningKitty-master.zip.
    #>

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $zipPath = ".\lib\HardeningKitty-master.zip"
    $destFolder = ".\lib"
    $kittyRoot = Join-Path $destFolder "HardeningKitty-master"

    Write-Host "[👽] $ts - Preparing HardeningKitty Audit..." -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-Path $zipPath)) {
        Write-Host "[💀] $ts - ZIP archive not found: $zipPath" -ForegroundColor Red
        return
    }

    Extract-ZipArchives -ZipPaths $zipPath -DestinationPath $destFolder -ConflictAction "Overwrite"

    $moduleFile = Get-ChildItem -Path $kittyRoot -Recurse -Filter "HardeningKitty.psm1" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $moduleFile) {
        Write-Host "[💀] $ts - Module not found after extraction: HardeningKitty.psm1" -ForegroundColor Red
        return
    }
    $kittyModule = $moduleFile.FullName

    try {
        Import-Module $kittyModule -Force -ErrorAction Stop
        Write-Host "[📦] $ts - Module imported: HardeningKitty" -ForegroundColor Green

        Write-Host "[🔍] $ts - Starting HardeningKitty in Audit mode..." -ForegroundColor Yellow
        Invoke-HardeningKitty -Mode Audit -EmojiSupport

        $messages = @(
            "[📋] HardeningKitty audit complete. Your system has been judged... by a cat.",
            "[🛸] Audit log submitted to the Intergalactic Security Council. Awaiting classification.",
            "[💾] Audit results stored. Results may cause existential crises for SOC interns.",
            "[👁️‍🗨️] CIA and DGSI bookmarked your report. DGSE and NSA thinks it's fake. GCHQ called it 'adorable'."
        )
        Write-Host "[🐾] $ts - Audit finished. No kittens were harmed in the process." -ForegroundColor Cyan
        Write-Host ($messages | Get-Random) -ForegroundColor DarkYellow
    }
    catch {
        Write-Host "[💀] $ts - Failed to run HardeningKitty audit: $_" -ForegroundColor Red
    }
}


function Set-WindowsDarkTheme {
    <#
    .SYNOPSIS
    Enables full dark mode for both Windows system UI and applications.

    .DESCRIPTION
    Sets registry values to apply dark mode for apps and system UI (taskbar, Start Menu, etc.).
    Greatly reduces photon emissions. Recommended for aliens, hackers, and nocturnal beings.

    .OUTPUTS
    Console status messages with alien-themed commentary.
    #>

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"

    try {
        Write-Host "[👽] $ts - Enabling Windows dark mode..." -ForegroundColor Cyan

        # Apps (Explorer, UWP, Settings)
        Set-ItemProperty -Path $regPath -Name "AppsUseLightTheme" -Value 0 -Type DWord -Force

        # System (Taskbar, Start Menu, Action Center)
        Set-ItemProperty -Path $regPath -Name "SystemUsesLightTheme" -Value 0 -Type DWord -Force

        Write-Host "[🌑] $ts - Darkness has been summoned. Welcome to the shadows." -ForegroundColor Green
    }
    catch {
        Write-Host "[💀] $ts - Failed to enable dark mode: $_" -ForegroundColor Red
    }
}


function Set-AccentColorVisibility {
    <#
    .SYNOPSIS
    Toggles accent color visibility on Start menu, taskbar, and window title bars.

    .DESCRIPTION
    Enables or disables the use of the system accent color on system UI elements such as the taskbar,
    Start menu, and window title bars by modifying the DWM registry key. Also allows forcing a pure black accent color.

    .PARAMETER Enable
    If $true, accent color is shown. If $false, it is hidden.

    .EXAMPLE
    Set-AccentColorVisibility -Enable $true

    .NOTES
    Registry: HKCU:\Software\Microsoft\Windows\DWM
    Keys: ColorPrevalence (DWORD), AccentColor (DWORD)
    #>

    param (
        [Parameter(Mandatory = $true)]
        [bool]$Enable
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $regPath = "HKCU:\Software\Microsoft\Windows\DWM"
    $value = if ($Enable) { 1 } else { 0 }

    try {
        Write-Host "[👽] $ts - Modifying accent color visibility in system UI..." -ForegroundColor Cyan
        Set-ItemProperty -Path $regPath -Name "ColorPrevalence" -Value $value -Type DWord -Force

        if ($Enable) {
            Write-Host "[🎨] $ts - Accent color ENABLED on taskbar and window title bars." -ForegroundColor Green

            # Force black accent color
            $blackAccent = 0x00000000
            Set-ItemProperty -Path $regPath -Name "AccentColor" -Value $blackAccent -Type DWord -Force
            Write-Host "[🖤] $ts - Accent color set to pitch black. Shadows are jealous." -ForegroundColor Gray
        } else {
            Write-Host "[🎨] $ts - Accent color DISABLED from system chrome." -ForegroundColor Green
        }
    } catch {
        Write-Host "[💀] $ts - Failed to modify accent color visibility: $_" -ForegroundColor Red
    }
}


function Remove-NonZipFiles {
    <#
    .SYNOPSIS
    Cleans one or more folders by removing all files and folders that are not .zip files.

    .DESCRIPTION
    Iterates over multiple folders and deletes everything that is not a .zip file.
    Useful to clean extracted content or binaries after usage.

    .PARAMETER TaskList
    One or more folder paths. In each, only .zip files will be preserved.

    .EXAMPLE
    Remove-NonZipFiles -TaskList ".\lib"

    .EXAMPLE
    Remove-NonZipFiles -TaskList @(".\lib", ".\src\softwares\DaVinci_Resolve\DaVinci_Resolve_19.1.4_Windows")
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string[]]$TaskList
    )

    foreach ($path in $TaskList) {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        if (-not (Test-Path $path)) {
            Write-Host "[💀] $ts - Folder does not exist: $path" -ForegroundColor Red
            continue
        }

        Write-Host "[👽] $ts - Cleaning folder: $path" -ForegroundColor Cyan
        Write-Host ""

        try {
            Get-ChildItem -Path $path -Force | ForEach-Object {
                if (-not ($_.PSIsContainer -eq $false -and $_.Extension -ieq ".zip")) {
                    Write-Host "[🧹] Removing: $($_.FullName)" -ForegroundColor DarkYellow
                    Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
                }
            }

            Write-Host "[✅] $ts - Clean completed for: $path" -ForegroundColor Green

            $messages = @(
                "[🛸] Non-zip content has been abducted. Folder sterilized.",
                "[🛸] Non-zip content has been abducted. Folder sterilized.",
                "[🛸] Non-zip content has been abducted. Folder sterilized.",
                "[🛸] Non-zip content has been abducted. Folder sterilized.",

                "[🧼] $path cleaned. Not even a cookie survived.",
                "[🪐] ZIPs preserved. Everything else got black-holed.",
                "[👁️] CIA checked twice. Only .zip files remain.",
                "[💣] Malware in $path self-destructed after seeing this cleanup."
            )
            Write-Host ($messages | Get-Random) -ForegroundColor DarkGray
        }
        catch {
            Write-Host ("[💀] {0} - Error cleaning {1}: {2}" -f $ts, $path, $_) -ForegroundColor Red
        }

        Write-Host ""
    }
}


function Create-FirefoxProfile {
    <#
    .SYNOPSIS
    👽 Creates a Firefox profile named 'root', handling collisions with style.

    .DESCRIPTION
    If no Firefox profiles exist, creates 'root'. If profiles exist:
    - With -Skip, exits if 'root' already exists.
    - With -Overwrite, deletes all other profiles and forces 'root'.

    .PARAMETER Overwrite
    Deletes all other profiles and keeps only 'root'.

    .PARAMETER Skip
    Skips creation if 'root' already exists.

    .NOTES
    Profile folder: $env:APPDATA\Mozilla\Firefox\Profiles
    #>

    param (
        [switch]$Overwrite,
        [switch]$Skip
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $firefoxPath = "C:\Program Files\Mozilla Firefox\firefox.exe"
    $profileRoot = "$env:APPDATA\Mozilla\Firefox\Profiles"

    if (-not (Test-Path $firefoxPath)) {
        Write-Host "[💀] $ts - Firefox not found: $firefoxPath" -ForegroundColor Red
        return
    }

    if (-not (Test-Path $profileRoot)) {
        New-Item -Path $profileRoot -ItemType Directory -Force | Out-Null
    }

    $existingProfiles = Get-ChildItem $profileRoot -Directory | Where-Object { $_.Name -match "\.(.+)$" }
    $existingProfileNames = $existingProfiles | ForEach-Object { $_.Name.Split('.')[-1] }

    if ($existingProfileNames -contains "root") {
        if ($Skip) {
            Write-Host "[🟡] $ts - Profile 'root' already exists. Skipping as requested." -ForegroundColor Yellow
            return
        }
        elseif ($Overwrite) {
            Write-Host "[🧨] $ts - Overwrite enabled. Nuking all profiles except 'root'..." -ForegroundColor Magenta
            $existingProfiles | Where-Object { $_.Name -notmatch "\.root$" } | ForEach-Object {
                Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "[💥] Removed: $($_.Name)" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "[⚠️] $ts - Profile 'root' already exists. Use -Skip or -Overwrite." -ForegroundColor Red
            return
        }
    }

    Write-Host "[🧪] $ts - Creating Firefox profile 'root'..." -ForegroundColor Cyan
    try {
        Push-Location (Split-Path $firefoxPath)
        & $firefoxPath -CreateProfile "root"
        Start-Sleep -Seconds 4.5
        & $firefoxPath -p "root"
        Start-Sleep -Seconds 4.5
        Stop-Process -Name "firefox" -Force -ErrorAction SilentlyContinue
        Write-Host "[✅] $ts - Firefox profile 'root' created and containment successful." -ForegroundColor Green
    }
    catch {
        Write-Host "[💀] $ts - Failed to create/launch Firefox profile: $_" -ForegroundColor Red
    }
    finally {
        Pop-Location
    }
}


function Initialize-UserDirectoryStructure {
    <#
    .SYNOPSIS
    👽 Initializes a personal multi-category directory structure (dev, learn, media, etc.).

    .DESCRIPTION
    Creates a set of structured folders under Documents, Music, Pictures, and Videos.
    Supports -Overwrite (deletes existing dirs) and -Skip (ignores existing ones).

    .PARAMETER Overwrite
    Deletes and recreates folders that already exist.

    .PARAMETER Skip
    Skips folder creation if the folder already exists.

    .NOTES
    Written by 🧠 extraterrestrial organization specialists.
    #>

    param (
        [switch]$Overwrite,
        [switch]$Skip
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[👽] $ts - Initializing your alien-grade personal directory structure..." -ForegroundColor Cyan

    if ($Overwrite -and $Skip) {
        Write-Host "[💀] Cannot use -Overwrite and -Skip together." -ForegroundColor Red
        return
    }

    $dirs = @(
        "$HOME\Documents\dev\works\asm",
        "$HOME\Documents\dev\works\c",
        "$HOME\Documents\dev\works\cpp",
        "$HOME\Documents\dev\works\go",
        "$HOME\Documents\dev\works\rust",
        "$HOME\Documents\dev\works\py",
        "$HOME\Documents\dev\works\web",
        "$HOME\Documents\dev\works\ps",
        "$HOME\Documents\dev\works\bat",
        "$HOME\Documents\dev\works\sh",
        "$HOME\Documents\dev\works\misc",
        "$HOME\Documents\dev\works\vagrant",
        "$HOME\Documents\dev\works\vbs",
        "$HOME\Documents\dev\etc",
        "$HOME\Documents\etc\books",
        "$HOME\Documents\it\conf",
        "$HOME\Documents\it\iso",
        "$HOME\Documents\it\vms",
        "$HOME\Documents\etc\med",
        "$HOME\Documents\etc\resume",
        "$HOME\Documents\etc\thoughts",
        "$HOME\Documents\etc\trainings\diet",
        "$HOME\Documents\etc\trainings\gym",
        "$HOME\Documents\learn\ai",
        "$HOME\Documents\learn\anki",
        "$HOME\Documents\learn\cheatsheets",
        "$HOME\Documents\learn\books",
        "$HOME\Documents\learn\notes",
        "$HOME\Documents\learn\misc",
        "$HOME\Documents\prvt\edu",
        "$HOME\Documents\prvt\etc\dox",
        "$HOME\Documents\prvt\etc\invoices",
        "$HOME\Documents\prvt\etc\legal",
        "$HOME\Documents\prvt\etc\finance",
        "$HOME\Documents\prvt\it\ssh",
        "$HOME\Documents\prvt\it\.kp",
        "$HOME\Documents\prvt\Obsidian",
        "$HOME\Documents\prvt\projects",
        "$HOME\Documents\prvt\works",
        "$HOME\Documents\sec\audits",
        "$HOME\Documents\sec\misc",
        "$HOME\Documents\sec\tools",
        "$HOME\Documents\sec\wsb",
        "$HOME\Music\music",
        "$HOME\Music\archives",
        "$HOME\Music\misc",
        "$HOME\Music\prvt",
        "$HOME\Music\edit",
        "$HOME\Pictures\design\works",
        "$HOME\Pictures\prvt\memories",
        "$HOME\Pictures\etc",
        "$HOME\Pictures\it",
        "$HOME\Pictures\misc",
        "$HOME\Pictures\wallpapers",
        "$HOME\Videos\edit",
        "$HOME\Videos\learn",
        "$HOME\Videos\dev",
        "$HOME\Videos\it",
        "$HOME\Videos\netw",
        "$HOME\Videos\trading",
        "$HOME\Videos\misc",
        "$HOME\Videos\prvt\memories"
    )

    foreach ($dir in $dirs) {
        try {
            if (Test-Path $dir) {
                if ($Overwrite) {
                    Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                    Write-Host "[💣] Overwritten: $dir" -ForegroundColor Magenta
                } elseif ($Skip) {
                    Write-Host "[⚠️] Skipped (already exists): $dir" -ForegroundColor Yellow
                } else {
                    Write-Host "[⚠️] Exists (no action): $dir" -ForegroundColor Gray
                }
            } else {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                Write-Host "[🛸] Created: $dir" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "[💀] Failed to process $dir : $_" -ForegroundColor Red
        }
    }

    $done = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "[✅] $done - All directories are in orbit. Galaxy structure deployed." -ForegroundColor Green
}


function Enable-WSL2 {
    <#
    .SYNOPSIS
    👽 Enables WSL 2 as the default version for future Linux distributions.

    .DESCRIPTION
    Checks if WSL is installed and sets the default version to 2 using `wsl.exe --set-default-version 2`.
    Displays an alien-grade status message depending on success or failure.

    .NOTES
    Requires: Windows 10 version 1903 or later (Build 18362+)
    #>

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    Write-Host "[👽] $ts - Activating WSL 2 as default..." -ForegroundColor Cyan

    if (-not (Get-Command "wsl.exe" -ErrorAction SilentlyContinue)) {
        Write-Host "[💀] $ts - WSL is not installed or not in PATH." -ForegroundColor Red
        return
    }

    try {
        wsl.exe --set-default-version 2
        Write-Host "[✅] $ts - WSL 2 is now the default version for all future distros." -ForegroundColor Green
    } catch {
        Write-Host "[💥] $ts - Failed to set WSL 2 as default: $_" -ForegroundColor Red
    }
}


function Apply-SystemConfiguration {
  Ensure-ComputerNameAndShow -DesiredName "root"
  Ensure-ComputerDescriptionAndShow
  Set-OEMInformation
  Ensure-WorkgroupAndShow -DesiredWorkgroup "DGSI"
  Set-DisplayExtendBottomTop
  Set-PowerSettings
  Pin-ToStartMenu -TargetPaths "C:\", "A:\"
  Disable-FastStartup
  Set-ClockToUTCTime
  Show-KnownExtensions
  Show-HiddenFiles
  Disable-RecentFiles
  Disable-FrequentFiles
  Show-SuperHiddenFiles
  Enable-GodMode
  Set-NumLockDefaultState
}


function Apply-WindowsTweaks {
  Disable-Telemetry
  Disable-ContentDeliveryManager
  Apply-PerformanceAndPrivacyTweaks
  Optimize-PerformanceSettings
  Optimize-NTFSSettings
}


function Apply-WallpaperAndUI {
  Copy-Wallpapers -SourcePath ".\src\images\wallpapers" -DestinationPath "C:\Wallpapers" -ConflictAction Skip
  Set-DesktopWallpaperFromImage -ImagePath "C:\wallpaper.png"
  # Set-DesktopWallpaperFromColor
  Set-WindowsDarkTheme
  Set-AccentColorVisibility -Enable $true
}


function Apply-SecurityBasics {
  Disable-UnnecessaryServices -ServiceList @("WerSvc", "OneSyncSvc", "PcaSvc", "MessagingService", "RetailDemo", "diagnosticshub.standardcollector.service", "lfsvc", "AJRouter", "RemoteRegistry", "DUSMsvc", "DiagTrack", "MapsBroker", "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", "dmwappushservice", "CdpUserSvc", "CdpSvc", "DiagSvc", "wisvc", "PhoneSvc", "UnistoreSvc")
  Write-Host ""
  Disable-UnwantedScheduledTasks -TaskList @("Microsoft\Windows\AppID\SmartScreenSpecific", "Microsoft\Windows\Application Experience\AitAgent", "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser", "Microsoft\Windows\Application Experience\ProgramDataUpdater", "Microsoft\Windows\Application Experience\StartupAppTask", "Microsoft\Windows\Autochk\Proxy", "Microsoft\Windows\CloudExperienceHost\CreateObjectTask", "Microsoft\Windows\Customer Experience Improvement Program\BthSQM", "Microsoft\Windows\Customer Experience Improvement Program\Consolidator", "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask", "Microsoft\Windows\Customer Experience Improvement Program\Uploader", "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip", "Microsoft\Windows\Maintenance\WinSAT", "Microsoft\Windows\PI\Sqm-Tasks", "Microsoft\Windows\Shell\FamilySafetyMonitor", "Microsoft\Windows\Shell\FamilySafetyRefresh", "Microsoft\Windows\Shell\FamilySafetyUpload", "Microsoft\Windows\Shell\FamilySafetyMonitorToastTask", "Microsoft\Windows\Shell\FamilySafetyRefreshTask", "Microsoft\Windows\WindowsUpdate\Automatic App Update", "Microsoft\Windows\NetTrace\GatherNetworkInfo", "Microsoft\Windows\Maps\MapsUpdateTask", "Microsoft\Windows\Maps\MapsToastTask", "Microsoft\XblGameSave\XblGameSaveTask", "Microsoft\XblGameSave\XblGameSaveTaskLogon")
  Write-Host ""
  Remove-BloatwarePackages -AppsList @("Microsoft.GetHelp", "Microsoft.People", "Microsoft.YourPhone", "Microsoft.GetStarted", "Microsoft.Messaging", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.Office.OneNote", "Microsoft.OneConnect", "Microsoft.SkypeApp", "Microsoft.CommsPhone", "Microsoft.Office.Sway", "Microsoft.WindowsFeedbackHub", "Microsoft.ConnectivityStore", "Microsoft.BingFoodAndDrink", "Microsoft.BingHealthAndFitness", "Microsoft.BingTravel", "Microsoft.WindowsReadingList", "DB6EA5DB.MediaSuiteEssentialsforDell", "DB6EA5DB.Power2GoforDell", "DB6EA5DB.PowerDirectorforDell", "DB6EA5DB.PowerMediaPlayerforDell", "DellInc.DellDigitalDelivery", "*Disney*", "*EclipseManager*", "*ActiproSoftwareLLC*", "*AdobeSystemsIncorporated.AdobePhotoshopExpress*", "*Duolingo-LearnLanguagesforFree*", "*PandoraMediaInc*", "*CandyCrush*", "*BubbleWitch3Saga*", "*Wunderlist*", "*Flipboard*", "*Royal Revolt*", "*Sway*", "*Speed Test*", "46928bounde.EclipseManager", "613EBCEA.PolarrPhotoEditorAcademicEdition", "7EE7776C.LinkedInforWindows", "89006A2E.AutodeskSketchBook", "ActiproSoftwareLLC.562882FEEB491", "CAF9E577.Plex", "ClearChannelRadioDigital.iHeartRadio", "Drawboard.DrawboardPDF", "Fitbit.FitbitCoach", "Flipboard.Flipboard", "KeeperSecurityInc.Keeper", "Microsoft.BingNews", "TheNewYorkTimes.NYTCrossword", "WinZipComputing.WinZipUniversal", "A278AB0D.MarchofEmpires", "6Wunderkinder.Wunderlist", "A278AB0D.DisneyMagicKingdoms", "2FE3CB00.PicsArt-PhotoStudio", "D52A8D61.FarmVille2CountryEscape", "D5EA27B7.Duolingo-LearnLanguagesforFree", "DB6EA5DB.CyberLinkMediaSuiteEssentials", "GAMELOFTSA.Asphalt8Airborne", "NORDCURRENT.COOKINGFEVER", "PandoraMediaInc.29680B314EFC2", "Playtika.CaesarsSlotsFreeCasino", "ShazamEntertainmentLtd.Shazam", "ThumbmunkeysLtd.PhototasticCollage", "TuneIn.TuneInRadio", "XINGAG.XING", "flaregamesGmbH.RoyalRevolt2", "king.com.*", "king.com.BubbleWitch3Saga", "king.com.CandyCrushSaga", "king.com.CandyCrushSodaSaga", "*Clipchamp*", "*Solitaire*")
  Write-Host ""
  Disable-UnneededFeatures -FeatureList @("MediaPlayback", "Printing-PrintToPDFServices-Features", "Print-Services", "MediaPlayback", "Printing-Foundation-Features", "Printing-Foundation-InternetPrinting-Client", "MSRDC-Infrastructure", "SmbDirect", "WorkFolders-Client")
}


function Install-CoreApplications {
  Install-NuGETProvider
  Write-Host ""
  Install-MSStoreAppByName -AppList @("TranslucentTB", "Lively Wallpaper", "ModernFlyouts (Preview)", "EarTrumpet", "MSI Center", "MSI Center Pro", "MSI Creator Center", "MSI Afterburner", "Netflix", "ChatGPT", "Nahimic", "Microsoft Copilot", "Interviewer Copilot", "Microsoft 365 Copilot", "Microsoft Teams", "Intel® Graphics Command Center", "FxSound")
  Write-Host ""
  Install-MSStoreAppById -AppIdList @("9PLFNLNT3G5G", "Guru3D.Afterburner", "ModernFlyouts.ModernFlyouts")
  Write-Host ""
  Install-WingetApplications -AppList @("Mozilla.Firefox", "GoLang.Go", "Oracle.JavaRuntimeEnvironment", "Syncthing.Syncthing", "Oracle.JDK.24", "Chocolatey.Chocolatey", "Chocolatey.ChocolateyGUI", "RustDesk.RustDesk", "Rustlang.Rustup", "Rustlang.Rust.GNU", "Rustlang.Rust.MSVC", "Rustlang.mdBook", "WildfireGames.0AD", "7zip.7zip", "Adobe.CreativeCloud", "Anki.Anki", "Audacity.Audacity", "Balena.Etcher", "BinanceTech.Binance", "PortSwigger.BurpSuite.Community", "Hex-Rays.IDA.Free", "Microsoft.WinDbg", "Mozilla.Firefox.DeveloperEdition", "Google.Chrome.Dev", "CrystalDewWorld.CrystalDiskInfo", "Nvidia.GeForceNow", "WinSCP.WinSCP", "WireGuard.WireGuard", "Nvidia.RTXVoice", "WiresharkFoundation.Wireshark", "VideoLAN.VLC", "Ubisoft.Connect", "SublimeHQ.SublimeText.4", "SteelSeries.GG", "SteelSeries.SteelSeriesEngine", "Sandboxie.Classic", "Piriform.Speccy", "PuTTY.PuTTY", "AutomatedLab", "JanDeDobbeleer.OhMyPosh", "Cockos.REAPER", "Oracle.VirtualBox", "OnionShare.OnionShare", "Microsoft.Office", "Obsidian.Obsidian", "Nvidia.CUDA", "OpenJS.NodeJS", "Mojang.MinecraftLauncher", "Microsoft.Teams", "Lazarus.Lazarus", "Maltego.Maltego", "HexChat.HexChat", "GOG.Galaxy", "Rufus.Rufus", "Giuspen.Cherrytree", "Obsidian.Obsidian", "yang991178.fluent-reader", "Opera.OperaGX", "Opera.Opera", "Opera.Opera.Dev", "MullvadVPN.MullvadBrowser", "NASM.NASM", "Git.Git", "GnuCash.GnuCash", "JetBrains.Hub", "Google.AndroidStudio", "Docker.DockerDesktop", "Docker.DockerCompose", "Docker.DockerCLI", "Kubernetes.kubectl", "Ollama.Ollama", "RazerInc.RazerInstaller", "RazerInc.RazerInstaller4", "Mixxx.Mixxx", "Transmission.Transmission", "martinrotter.RSSGuard", "Proton.ProtonVPN", "Proton.ProtonPass", "Proton.ProtonMailBridge", "Proton.ProtonMail", "Proton.ProtonDrive", "SleuthKit.Autopsy", "BleachBit.BleachBit", "mRemoteNG.mRemoteNG", "WinDirStat.WinDirStat", "Xmind.Xmind", "OpenVPNTechnologies.OpenVPN", "Python.Python.3.13", "Discord.Discord", "Element.Element", "Notepad++.Notepad++", "Brave.Brave", "TheDocumentFoundation.LibreOffice", "7zip.7zip", "AppWork.JDownloader", "Microsoft.VisualStudio.2022.Entreprise", "EpicGames.EpicGamesLauncher", "Mozilla.Thunderbird", "Microsoft.WindowsTerminal", "Google.Chrome", "ModernFlyouts.ModernFlyouts", "Guru3D.Afterburner", "Valve.Steam", "VideoLAN.VLC", "ShareX.ShareX", "Cygwin.Cygwin", "MSYS2.MSYS2", "vim.vim", "qBittorrent.qBittorrent", "Rainmeter.Rainmeter", "MullvadVPN.MullvadVPN", "OBSProject.OBSStudio", "Microsoft.Sysinternals", "Microsoft.Sysinternals.ProcessExplorer", "Microsoft.Sysinternals.TCPView", "Microsoft.Sysinternals.BGInfo", "Microsoft.Sysinternals.Autoruns", "Microsoft.Sysinternals.Desktops", "Microsoft.Sysinternals.ProcessMonitor", "Microsoft.Sysinternals.PsTools", "Microsoft.Sysinternals.Strings", "Microsoft.Sysinternals.Sysmon", "Microsoft.Sysinternals.TCPView", "Microsoft.Sysinternals.Whois", "KeePassXCTeam.KeePassXC", "AutoHotkey.AutoHotkey", "IDRIX.VeraCrypt", "TorProject.TorBrowser", "voidtools.Everything", "HandBrake.HandBrake", "OpenWhisperSystems.Signal", "RiotGames.Valorant.EU", "OpenWhisperSystems.Signal", "Microsoft.AIShell", "GIMP.GIMP", "Pinta.Pinta", "Krita.Krita", "OpenVPNTechnologies.OpenVPNConnect", "Microsoft.VCRedist.2013.x64", "Microsoft.VCRedist.2005.x64", "Microsoft.VCRedist.2008.x64", "Microsoft.VCRedist.2010.x64", "Microsoft.VCRedist.2012.x64", "Microsoft.VCRedist.2015+.x64", "Microsoft.VCRedist.2005.x86", "Microsoft.VCRedist.2008.x86", "Microsoft.VCRedist.2012.x86", "Microsoft.VCRedist.2013.x86", "nomic.gpt4all", "Telegram.TelegramDesktop", "TeamViewer.TeamViewer", "SlackTechnologies.Slack", "Hashicorp.Vagrant", "Microsoft.VCRedist.2015+.arm64", "Rizin.Cutter", "OO-Software.ShutUp10", "Logseq.Logseq", "Microsoft.PowerToys", "Hashicorp.Terraform", "Axosoft.GitKraken", "ElementLabs.LMStudio", "Yubico.YubikeyManager", "Yubico.YubiKeyManagerCLI", "VSCodium.VSCodium", "Microsoft .NET SDK 9.0", "Microsoft.VisualStudio.2022.BuildTools", "Microsoft.VisualStudio.2019.BuildTools", "hasherezade.PE-bear", "Insecure.Nmap", "OnionShare.OnionShare", "OliverBetz.ExifTool", "dnSpyEx.dnSpy", "SyncTrayzor.SyncTrayzor", "XAMPP 8.2")
  Write-Host ""
  Alter-PathVariable -Paths 
  @("$env:USERPROFILE\AppData\Local\Programs\Python\Python311", "$env:USERPROFILE\AppData\Roaming\Python\Python311\Scripts", "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin", "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin", "$env:USERPROFILE\AppData\Roaming\npm", "$env:USERPROFILE\go\bin", "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin", "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin", "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin", "C:\Program Files\dotnet", "C:\Program Files\JetBrains\Toolbox\scripts", "C:\Tools\x64dbg", "C:\Tools\PE-bear", "C:\Tools\dnSpyEx", "C:\Tools\Cutter", "C:\Tools\Ghidra", "C:\Tools\Velociraptor", "C:\Tools\Nmap", "C:\Tools", "C:\HashiCorp\Vagrant\bin", "C:\Program Files\Terraform", "C:\Program Files\OpenVPN Connect", "C:\Program Files\WireGuard", "C:\Program Files\PowerToys", "C:\Program Files\AutoHotkey", "$env:USERPROFILE\.dotnet\tools", "$env:USERPROFILE\scoop\shims")
  Write-Host ""
  Install-Executables -ExecutableNames @("Ankama Launcher-Setup.exe", "OfficeSetup.exe")
  # Install-Executables -ExecutableNames @("Ankama Launcher-Setup.exe", "OfficeSetup.exe", "Rockstar-Games-Launcher.exe")
  # Write-Host ""
  # Install-eDEX
  # Write-Host ""
  # Install-DaVinciResolve
}

function Apply-AdvancedSecurityHardening {
  Execute-HardeningKitty
  Write-Host ""
  Audit-HardeningKitty
}


function Setup-Environment {
  Create-FirefoxProfile -Overwrite
  Initialize-UserDirectoryStructure -Overwrite
}


function main {
  if (-not (Test-AdminRights)) {
    Write-Host "[!] You must run this script as an administrator." -ForegroundColor Red
    return
  }

	[Console]::Clear()
	Show-Banner -ForegroundColor Green
	
	Write-Host ""
	Write-Host "👽 WinPostInstall - Post-installation by aliens, for humans 🛸"
	Write-Host ""
	
	$info = Get-SystemInfoData
  Write-Host "[👽] $($info.Timestamp) - Gathering system information..." -ForegroundColor Cyan
  Write-Host ""
  Write-Host "[👽] Hostname: $($info.Hostname)" -ForegroundColor Cyan
  Write-Host "[👽] Domain: $($info.Domain)" -ForegroundColor Cyan
  Write-Host ""

  Invoke-FirewallHardening
  Write-Host ""
  Apply-SystemConfiguration
  Write-Host ""
  Apply-WindowsTweaks
  Write-Host ""
  Apply-WallpaperAndUI
  Write-Host ""
  Apply-SecurityBasics
  Write-Host ""
  Enable-RequiredFeatures -FeatureList @("HypervisorPlatform", "Microsoft-Hyper-V-All", "Microsoft-Hyper-V-Tools-All", "VirtualMachinePlatform", "Containers-DisposableClientVM", "Microsoft-Windows-Subsystem-Linux")
  Write-Host ""
  Enable-VirtualizationSecurityFeatures
  Write-Host ""
  Enable-WindowsDefenderAdvancedProtection
  Write-Host ""
  Install-CoreApplications
  Write-Host ""
  Apply-AdvancedSecurityHardening
  Write-Host ""
  Refresh-GroupPolicyAndWSUS
  Write-Host ""
  Setup-Environment
  Write-Host ""
  Remove-NonZipFiles -TaskList @(".\lib", ".\src\softwares\DaVinci_Resolve\DaVinci_Resolve_19.1.4_Windows")
  Write-Host ""
  Install-WindowsUpdates
  Write-Host ""
  Restart-System
}


if ($Help) {
  Display-Help
  return
  } elseif ($AfterRestart) {
  Enable-WSL2
  Install-WingetApplications -AppList @("Debian.Debian", "Canonical.Ubuntu", "OffSec.KaliLinux")
  Install-WindowsUpdates
  Remove-BloatwarePackages -AppsList @("Microsoft.GetHelp", "Microsoft.People", "Microsoft.YourPhone", "Microsoft.GetStarted", "Microsoft.Messaging", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.Office.OneNote", "Microsoft.OneConnect", "Microsoft.SkypeApp", "Microsoft.CommsPhone", "Microsoft.Office.Sway", "Microsoft.WindowsFeedbackHub", "Microsoft.ConnectivityStore", "Microsoft.BingFoodAndDrink", "Microsoft.BingHealthAndFitness", "Microsoft.BingTravel", "Microsoft.WindowsReadingList", "DB6EA5DB.MediaSuiteEssentialsforDell", "DB6EA5DB.Power2GoforDell", "DB6EA5DB.PowerDirectorforDell", "DB6EA5DB.PowerMediaPlayerforDell", "DellInc.DellDigitalDelivery", "*Disney*", "*EclipseManager*", "*ActiproSoftwareLLC*", "*AdobeSystemsIncorporated.AdobePhotoshopExpress*", "*Duolingo-LearnLanguagesforFree*", "*PandoraMediaInc*", "*CandyCrush*", "*BubbleWitch3Saga*", "*Wunderlist*", "*Flipboard*", "*Royal Revolt*", "*Sway*", "*Speed Test*", "46928bounde.EclipseManager", "613EBCEA.PolarrPhotoEditorAcademicEdition", "7EE7776C.LinkedInforWindows", "89006A2E.AutodeskSketchBook", "ActiproSoftwareLLC.562882FEEB491", "CAF9E577.Plex", "ClearChannelRadioDigital.iHeartRadio", "Drawboard.DrawboardPDF", "Fitbit.FitbitCoach", "Flipboard.Flipboard", "KeeperSecurityInc.Keeper", "Microsoft.BingNews", "TheNewYorkTimes.NYTCrossword", "WinZipComputing.WinZipUniversal", "A278AB0D.MarchofEmpires", "6Wunderkinder.Wunderlist", "A278AB0D.DisneyMagicKingdoms", "2FE3CB00.PicsArt-PhotoStudio", "D52A8D61.FarmVille2CountryEscape", "D5EA27B7.Duolingo-LearnLanguagesforFree", "DB6EA5DB.CyberLinkMediaSuiteEssentials", "GAMELOFTSA.Asphalt8Airborne", "NORDCURRENT.COOKINGFEVER", "PandoraMediaInc.29680B314EFC2", "Playtika.CaesarsSlotsFreeCasino", "ShazamEntertainmentLtd.Shazam", "ThumbmunkeysLtd.PhototasticCollage", "TuneIn.TuneInRadio", "XINGAG.XING", "flaregamesGmbH.RoyalRevolt2", "king.com.*", "king.com.BubbleWitch3Saga", "king.com.CandyCrushSaga", "king.com.CandyCrushSodaSaga", "*Clipchamp*", "*Solitaire*")
  } else {
  main
  }
