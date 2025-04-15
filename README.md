<div id="top" align="center">

<!-- Shields Header -->
[![Contributors][contributors-shield]](https://github.com/franckferman/Win-PostInstall/graphs/contributors)
[![Forks][forks-shield]](https://github.com/franckferman/Win-PostInstall/network/members)
[![Stargazers][stars-shield]](https://github.com/franckferman/Win-PostInstall/stargazers)
[![Issues][issues-shield]](https://github.com/franckferman/Win-PostInstall/issues)
[![License][license-shield]](https://github.com/franckferman/Win-PostInstall/blob/stable/LICENSE)

<!-- Title & Tagline -->
<h3 align="center">👽 Win-PostInstall</h3>
<p align="center">
    <em>🛸 Alien-grade post-install automation for Windows deployments</em><br>
    Automate. Harden. Customize.<br>
    A PowerShell script for paranoid sysadmins, red teamers & sovereign devs.<br>
    <strong>Windows, your way — not from Earth. Definitely not from Redmond.</strong>
</p>

</div>

## 📜 Table of Contents

<details open>
  <summary><strong>Click to collapse/expand</strong></summary>
  <ol>
    <li><a href="#-about">📖 About</a></li>
    <li><a href="#-installation">🛠️ Installation</a></li>
    <li><a href="#-usage">🎮 Usage</a></li>
    <li><a href="#-contributing">🤝 Contributing</a></li>
    <li><a href="#-star-evolution">🌠 Star Evolution</a></li>
    <li><a href="#-license">📜 License</a></li>
    <li><a href="#-contact">📞 Contact</a></li>
  </ol>
</details>

## 📖 About

WinPostInstall is a modular and stealthy PowerShell script that fully automates post-installation on Windows systems.

Originally developed on Windows 11 and tested across several setups, it's meant to reproduce my ideal system setup in a single run: hardened, minimal, themed, tooled, and private.

> ⚙️ Note: This script is under active development — not production-grade yet. Treat it as a strong baseline and expect regular improvements.

It leans on native PowerShell, WinGet, Store integration, optional EXE packages, and WSL tooling — and thus should work on a wide range of modern Windows versions. Only Windows 11 is officially supported for now.

> ⚠️ Issues on other versions? PRs and reports are welcome.

### 💡 Goal

Crafted for red teamers, sysadmins, and aliens who expect more than Windows-as-a-service.

- ⚙️ Hardened, secure, and reproducible setup — built around privacy, performance, and minimalism.
- 🌑 Fully themed dark UI and terminal.
- 🔐 Secure by default: disables legacy components, noisy services, and telemetry.
- 🛠️ Dev & Ops ready:
  - Oh-My-Posh + Powerlevel10k
  - Custom aliases, plugins, and shell tuning
  - WSL2, Exegol, and full offensive toolchains

> Your machine, your rules. Hardened, stripped, elegant.

➡️ A fully optimized, secured, and ready-to-use Windows system — zero manual tweaks needed.

Because I’m detail-obsessed (some say perfectionist — I say precise), every aspect must match: appearance, usability, performance, privacy, and security.

> I built this script to get the exact system I need — consistently, efficiently, and silently.

This script ensures your machine is:

- 🛡️ Hardened against telemetry and common APT tradecraft.
- 🧹 Purged of bloatware, spyware, and corporate-grade nonsense.
- 🧰 Preloaded with hundreds of curated tools (WinGet, Store, direct EXEs).
- 🎨 Themed with clean dark UI, shell, and wallpapers.
- 🧬 Ready for offensive security, reverse engineering, dev, and automation.

All of that — with sarcasm, emojis, and APT-style stealth. ✨

### 📦 Features

- 📦 System Configuration
  - ✅ Set custom computer name
  - ✅ Set computer description
  - ✅ Define OEM information
  - ✅ Set workgroup
  - ✅ Configure multi-monitor display (extend bottom-top)
  - ✅ Apply power settings
  - ✅ Pin drives C:\ and A:\ to Start Menu
  - ✅ Disable Fast Startup
  - ✅ Set system clock to UTC
  - ✅ Show file extensions
  - ✅ Show hidden files
  - ✅ Disable Recent Files and Frequent Folders
  - ✅ Show super hidden files
  - ✅ Enable God Mode folder
  - ✅ Enable NumLock by default on boot
- 🧰 Windows Tweaks
  - ✅ Disable Telemetry
  - ✅ Disable Content Delivery Manager
  - ✅ Apply performance and privacy optimizations
  - ✅ Optimize NTFS file system parameters
  - ✅ Optimize system performance settings
- 🎨 Wallpaper & UI
  - ✅ Copy wallpapers to C:\Wallpapers
  - ✅ Set a specific image as desktop background
  - ✅ Enable Dark Theme
  - ✅ Show accent color on Start/Taskbar
- 🔐 Basic Security Hardening
  - ✅ Disable unnecessary services (e.g., Xbox, Telemetry, RemoteRegistry, etc.)
  - ✅ Disable scheduled tasks tied to CEIP, SmartScreen, Xbox, Maps, etc.
  - ✅ Remove preinstalled bloatware and OEM packages (e.g., Candy Crush, OneConnect, Skype, Flipboard)
  - ✅ Disable optional Windows features like Internet Printing, PDF Print, SMB Direct, WorkFolders, RDC
- 📦 Core Applications Installation
  - ⏬ Microsoft Store apps by Name:
    - Tools like EarTrumpet, Lively Wallpaper, ModernFlyouts, MSI Center, Copilot, FxSound, etc.
  - ⏬ Microsoft Store apps by ID:
    - Afterburner, ModernFlyouts, etc.
  - ⏬ Winget Applications:
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
  - 📂 Executable Installations:
    - Run offline .exe files like Ankama Launcher, OfficeSetup, wsl_update_x64.msi
- 🔁 Path Variable Management:
  - Add useful dev/security tool directories to the system PATH
- 🛡️ Advanced Security Hardening
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
- 🧬 Environment Setup
  - Create and configure a new Firefox Profile
  - Create a custom directory structure for user data
- 🧪 WSL + Exegol Deployment
  - Guide user through enabling WSL + Docker integration
  - Install pipx, Exegol, and argcomplete
  - Generate and import PowerShell tab-completion for Exegol
  - Add completion script to PowerShell profile
- 🔄 Post-Restart Flow
  - Executed if script is called with -AfterRestart:
    - Re-install wsl_update_x64.msi
    - Enable WSL2
    - Install WSL distros: Debian, Ubuntu, Kali
    - Re-run bloatware removal
    - Setup Exegol after reboot
- 🛸 Style and Experience
  - Modular structure with timestamped output
  - Stylized UX with 👽 emojis, colored messages, sarcastic jokes
  - Banner display via Show-Banner
  - Full admin check at start
  - Final system reboot

> Compatibility with other versions (LTSC, Server editions, Insider builds...) is *possible* (probable), but not guaranteed.  

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🚀 Installation

### 📥 **Direct Download** from GitHub

1. Go to GitHub repo.
2. Click `<> Code` → `Download ZIP`.
3. Extract the archive to your desired location.

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🎮 Usage

1. Temporarily allow script execution:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
```

> 🛑 Important: This command temporarily adjusts the execution policy to allow script execution for the current process only, minimizing security risks. 
> Always examine scripts before executing them to ensure safety.

2. Run the script:
```powershell
.\WinPostInstall.ps1
```

Alternatively, for a streamlined approach, combine the execution policy adjustment with script launch in a single line:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process; .\WinPostInstall.ps1
```

> ⚠️ **Note**: This script must be run **as Administrator**. It will request administrator privileges automatically at start.

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🤝 Contributing

We truly appreciate and welcome community involvement. Your contributions, feedback, and suggestions play a crucial role in improving the project for everyone. If you're interested in contributing or have ideas for enhancements, please feel free to open an issue or submit a pull request on our GitHub repository. Every contribution, no matter how big or small, is highly valued and greatly appreciated!

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 🌠 Star Evolution

Explore the star history of this project and see how it has evolved over time:

<a href="https://star-history.com/#franckferman/Win-PostInstall&Timeline">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=franckferman/Win-PostInstall&type=Timeline&theme=dark" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=franckferman/Win-PostInstall&type=Timeline" />
  </picture>
</a>

Your support is greatly appreciated. We're grateful for every star! Your backing fuels our passion. ✨

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 📚 License

This project is licensed under the GNU Affero General Public License, Version 3.0. For more details, please refer to the LICENSE file in the repository: [Read the license on GitHub](https://github.com/franckferman/Win-PostInstall/blob/stable/LICENSE)

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

## 📞 Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

<p align="right">(<a href="#top">🔼 Back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/franckferman/Win-PostInstall.svg?style=for-the-badge
[contributors-url]: https://github.com/franckferman/Win-PostInstall/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/franckferman/Win-PostInstall.svg?style=for-the-badge
[forks-url]: https://github.com/franckferman/Win-PostInstall/network/members
[stars-shield]: https://img.shields.io/github/stars/franckferman/Win-PostInstall.svg?style=for-the-badge
[stars-url]: https://github.com/franckferman/Win-PostInstall/stargazers
[issues-shield]: https://img.shields.io/github/issues/franckferman/Win-PostInstall.svg?style=for-the-badge
[issues-url]: https://github.com/franckferman/Win-PostInstall/issues
[license-shield]: https://img.shields.io/github/license/franckferman/Win-PostInstall.svg?style=for-the-badge
[license-url]: https://github.com/franckferman/Win-PostInstall/blob/stable/LICENSE
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue

