# 👽 `WinPostInstall.ps1` – 🛸 Alien-grade Post-Install Automation for Windows.

A highly modular, stealthy, and humorous PowerShell script designed to fully automate the post-installation process of Windows systems.  
Crafted for professionals, aliens, red teams, and paranoid sysadmins alike, it combines deep system hardening, bloatware purging, UI personalization, advanced Defender configuration, development and hacking toolchains, WSL/Exegol deployment, and much more.

This script ensures your machine is:
- Hardened against telemetry and common APT tradecraft
- Purged of bloatware, spyware, and retail-grade nonsense
- Preloaded with hundreds of curated tools (winget, store, direct EXEs)
- Beautified with dark themes and wallpapers
- Ready for offensive security, reverse engineering, development, and creativity

All that, with emojis, sarcasm, and APT-style stealth ✨

## Features

### 🛠️ System Configuration

- Set custom computer name (root)
- Set computer description
- Define OEM information
- Set workgroup to DGSI
- Configure multi-monitor display (extend bottom-top)
- Apply power settings
- Pin drives C:\ and A:\ to Start Menu
- Disable Fast Startup
- Set system clock to UTC
- Show file extensions
- Show hidden files
- Disable Recent Files and Frequent Folders
- Show super hidden files
- Enable God Mode folder
- Enable NumLock by default on boot

### 🧰 Windows Tweaks

- Disable Telemetry
- Disable Content Delivery Manager
- Apply performance and privacy optimizations
- Optimize NTFS file system parameters
- Optimize system performance settings

### 🎨 Wallpaper & UI

- Copy wallpapers to C:\Wallpapers
- Set a specific image as desktop background
- Enable Dark Theme
- Show accent color on Start/Taskbar

### 🔐 Basic Security Hardening

- Disable unnecessary services (e.g., Xbox, Telemetry, RemoteRegistry, etc.)
- Disable scheduled tasks tied to CEIP, SmartScreen, Xbox, Maps, etc.
- Remove preinstalled bloatware and OEM packages (e.g., Candy Crush, OneConnect, Skype, Flipboard)
- Disable optional Windows features like Internet Printing, PDF Print, SMB Direct, WorkFolders, RDC

### 📦 Core Applications Installation

#### ⏬ Microsoft Store apps by Name:

- Tools like EarTrumpet, Lively Wallpaper, ModernFlyouts, MSI Center, Copilot, FxSound, etc.

#### ⏬ Microsoft Store apps by ID:

- Afterburner, ModernFlyouts, etc.

#### ⏬ Winget Applications:

- Browsers: Firefox (stable & dev), Brave, Opera GX, Mullvad Browser, Tor Browser
- Languages: Go, Java JRE/JDK, Python, Rust (+ toolchains), Node.js
- Security: Burp Suite, IDA Free, WireGuard, Wireshark, VeraCrypt, KeePassXC, Sysinternals Suite, Nmap
- Dev tools: Visual Studio 2022/2019 Build Tools, Git, GitLFS, Terraform, Vagrant, Docker, Kubernetes, VSCode (Codium), Chocolatey, Notepad++, Anki, Sublime Text
- Privacy tools: ProtonMail, ProtonVPN, Signal, OnionShare
- Creative tools: OBS Studio, GIMP, Pinta, Krita, DaVinci Resolve (optional)
- Media & utilities: VLC, Audacity, ShareX, 7zip, WinDirStat, BleachBit, RSS readers
- Reverse engineering: dnSpy, PE-bear, Rizin Cutter
- Gaming & launchers: Steam, Epic Games, Ubisoft, Minecraft Launcher, Valorant
- Office & productivity: LibreOffice, Microsoft Office, Logseq, Obsidian
- Extras: REAPER, Discord, Telegram, TeamViewer, AutoHotkey, PowerToys, ExifTool

#### 📂 Executable Installations:

- Run offline .exe files like Ankama Launcher, OfficeSetup, wsl_update_x64.msi

### 🔁 Path Variable Management:

- Add useful dev/security tool directories to the system PATH

### 🛡️ Advanced Security Hardening

- Execute and audit HardeningKitty configuration baseline
- Apply custom Windows Firewall hardening
- Enable key Windows Defender features:
  - Exploit Protection
  - Controlled Folder Access
  - ASR (Attack Surface Reduction) rules
  - Real-time protection, cloud MAPS, Defender signature updates
  - Threat scanning and remediation
- Enable Virtualization-based Security (VBS) features
- Enable WDAC (Windows Defender Application Control)
- Refresh Group Policies & WSUS

### 🧬 Environment Setup

- Create and configure a new Firefox Profile
- Create a custom directory structure for user data

### 🧪 WSL + Exegol Deployment

- Guide user through enabling WSL + Docker integration
- Install pipx, Exegol, and argcomplete
- Generate and import PowerShell tab-completion for Exegol
- Add completion script to PowerShell profile

### 🔄 Post-Restart Flow

Executed if script is called with -AfterRestart:

- Re-install wsl_update_x64.msi
- Enable WSL2
- Install WSL distros: Debian, Ubuntu, Kali
- Re-run bloatware removal
- Setup Exegol after reboot

### 🛸 Style and Experience

- Modular structure with timestamped output
- Stylized UX with 👽 emojis, colored messages, sarcastic jokes
- Banner display via Show-Banner
- Full admin check at start
- Final system reboot

