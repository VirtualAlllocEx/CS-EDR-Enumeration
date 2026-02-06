# CS-EDR-Enumeration

Cobalt Strike Aggressor Script for enumerating AV, EPP, EDR, and Telemetry/SIEM products on compromised Windows hosts. Provides **six enumeration commands** with different noise footprints, letting operators choose the method that fits their current risk tolerance.

![Cobalt Strike](https://img.shields.io/badge/Cobalt%20Strike-4.x-red)
![License](https://img.shields.io/badge/License-MIT-green)

## Why This Exists

Knowing what security products are running on a host is the first question after initial access. The problem: most enumeration techniques spawn `powershell.exe` or `cmd.exe`, generating telemetry that the very EDR you're trying to identify will flag. The irony of spawning the most-monitored process on the system to ask whether the system is monitored shouldn't be lost on anyone.

This script provides a graduated approach — from completely silent (in-process BOF, zero artifacts) to full WMI enumeration — so operators can make informed decisions about detection tradeoffs.

## Features

- **126 process signatures** and **73 service signatures** covering 30+ security vendors
- **Six commands** sorted by noise level from `*` (silent) to `****` (loud)
- Inline BOF for service enumeration — zero child processes, no AMSI/CLR/ETW
- Automatic threat level assessment (HIGH / MODERATE / LOW)
- Color-coded output by product category: `[EDR]` `[AV]` `[EPP]` `[TEL]`
- Vendor-specific tactical guidance when threats are detected
- Built-in `edr_help` command with full artifact comparison matrix

## Supported Vendors

| Category | Vendors |
|----------|---------|
| **EDR** | CrowdStrike, SentinelOne, Carbon Black, Microsoft Defender for Endpoint, Cortex XDR, Elastic Security, Sophos Intercept X, Trend Micro Apex One, Trellix/FireEye, ESET Inspect, Bitdefender GravityZone, Cybereason, Fortinet FortiEDR, HarfangLab, Huntress, Deep Instinct, LimaCharlie, Rapid7, Tanium |
| **AV** | Microsoft Defender, ESET, Kaspersky, Sophos, McAfee/Trellix, Trend Micro, Bitdefender, Webroot, Malwarebytes, WithSecure/F-Secure |
| **EPP** | Broadcom/Symantec, BlackBerry Cylance, WatchGuard/Panda, Tanium |
| **Telemetry/SIEM** | Sysmon, Splunk UF, Elastic Beats, Wazuh/OSSEC, Velociraptor |

## Command Reference

Commands sorted by noise level (lowest → highest):

| Command | Noise | Method | Child Process | CLR | AMSI | ScriptBlock Log |
|---------|-------|--------|---------------|-----|------|-----------------|
| `edr_check` | ★ | `bps()` process list | — | — | — | — |
| `edr_services_bof` | ★ | Inline BOF (`beacon_inline_execute`) | — | — | — | — |
| `edr_services_pick` | ★★ | `bpowerpick` (unmanaged PowerShell) | — | Yes | Yes | — |
| `edr_services_cmd` | ★★★ | `bshell` + `sc query` | cmd.exe | — | — | — |
| `edr_services` | ★★★★ | `bpowershell` + `Get-Service` | powershell.exe | Yes | Yes | Yes |
| `edr_enum` | ★★★★ | `bps()` + PowerShell WMI | powershell.exe | Yes | Yes | Yes |

### Recommended Workflow

```
1. edr_check            ★     Always. Zero cost.
2. edr_services_bof     ★     If BOF is compiled. Zero cost.
3. edr_services_pick    ★★    If CLR loading is acceptable.
4. edr_services_cmd     ★★★   If cmd.exe child is acceptable.
5. edr_services         ★★★★  Only if PowerShell is already expected.
6. edr_enum             ★★★★  Full picture, highest artifact cost.
```

**Best combo:** `edr_check` + `edr_services_bof` = full process AND service visibility at noise level ★ with zero extra artifacts.

## Installation

### 1. Load the Aggressor Script

Copy `edr-enum.cna` into your Cobalt Strike client:

```
Cobalt Strike → Script Manager → Load → edr-enum.cna
```

This gives you immediate access to `edr_check`, `edr_services`, `edr_services_cmd`, `edr_services_pick`, and `edr_enum`. No compilation required for these.

### 2. Compile the BOF (for `edr_services_bof`)

The BOF requires MinGW-w64 cross-compilers. On Kali/Debian/Ubuntu:

```bash
sudo apt install mingw-w64
```

Then compile using the provided Makefile:

```bash
make
```

Or manually:

```bash
# x64
x86_64-w64-mingw32-gcc -c svc_enum_bof.c -o svc_enum_bof_x64.o

# x86
i686-w64-mingw32-gcc -c svc_enum_bof.c -o svc_enum_bof_x86.o
```

Place the compiled `.o` files in the **same directory** as `edr-enum.cna`.

## File Structure

```
CS-EDR-Enumeration/
├── edr-enum.cna          # Aggressor Script (main script)
├── svc_enum_bof.c        # BOF source for service enumeration
├── beacon.h              # Cobalt Strike BOF API header
├── Makefile              # Cross-compilation build script
└── README.md
```

## Output Examples

### Process-Based Enumeration (`edr_check`)

Uses Beacon's native `bps()` — no child process, no DLL loads, no ETW. Zero artifacts.

<img width="700" height="812" alt="image" src="https://github.com/user-attachments/assets/aa2f00ae-74aa-4db0-ae3a-f4762ab36e13" />

### BOF Service Enumeration (`edr_services_bof`)

In-process service enumeration via `OpenSCManagerW` + `EnumServicesStatusExW`. Same noise level as `edr_check`.

<img width="700" height="943" alt="image" src="https://github.com/user-attachments/assets/4b91bf47-04dc-44cd-8ac9-cc695c37500d" />

### Other Methods

<details>
<summary>bpowerpick — Unmanaged PowerShell (★★)</summary>

<img width="700" height="939" alt="image" src="https://github.com/user-attachments/assets/7ebd8eec-c7b3-4da8-b9ca-8694e272d2f5" />

Loads CLR into Beacon process. No `powershell.exe` child, but EDRs may flag unmanaged CLR hosting.
</details>

<details>
<summary>bpowershell — PowerShell Get-Service (★★★★)</summary>

<img width="700" height="926" alt="image" src="https://github.com/user-attachments/assets/d8075abc-67b3-4e2c-b28e-f28d0bbc699f" />

Spawns `powershell.exe` — activates ScriptBlock logging, Module logging, AMSI, and process creation events.
</details>

<details>
<summary>bshell — cmd.exe sc query (★★★)</summary>

<img width="700" height="981" alt="image" src="https://github.com/user-attachments/assets/5ded11af-71c8-4606-bb89-b3c0437ce0f8" />

Spawns `cmd.exe`. Logged in Sysmon EID 1 / Windows EID 4688 with command line. No CLR, no AMSI, no PS telemetry.
</details>

## Noise Rating Explained

The script uses **NOISE** rather than "OPSEC" ratings deliberately. "OPSEC: ★★★★" looks like a good thing — four stars of something you want. NOISE makes the scale intuitive: **more stars = worse**.

| Level | Label | What Lights Up |
|-------|-------|----------------|
| ★ | MINIMAL | Nothing. Beacon-native, in-process only. |
| ★★ | LOW | CLR loaded into Beacon. `.NET Runtime` ETW. AMSI init. |
| ★★★ | MODERATE | Child process (`cmd.exe`). Sysmon EID 1, Windows EID 4688. |
| ★★★★ | HIGH | `powershell.exe`. ScriptBlock, Module Log, AMSI, full ETW. |

> **Key insight:** ★★ and ★★★ open *different* detection surfaces, not additive ones. `cmd.exe` does not load CLR; `bpowerpick` does not spawn a child process. The star count reflects overall detection likelihood.

## Malleable C2 Dependency

Commands that spawn child processes (`bshell`, `bpowershell`, `bpowerpick`) use your Malleable C2 profile's `.post-ex.spawnto` settings. The parent-child lineage is often **more detectable** than the command content itself. Make sure your `spawnto` binary plausibly spawns `cmd.exe` or `powershell.exe` in the target environment.

## BOF Technical Details

The BOF (`svc_enum_bof.c`) enumerates running Win32 services via the Service Control Manager API:

- Opens `SCManager` with `SC_MANAGER_ENUMERATE_SERVICE`
- Calls `EnumServicesStatusExW` to list all active Win32 services
- Converts wide service names to narrow (UTF-8) for signature matching
- Outputs via Beacon's format API as a single contiguous blob

All API calls use Dynamic Function Resolution (DFR) — standard for BOFs. No static imports, no IAT entries.

## Contributing

PRs welcome for new vendor signatures. The format is straightforward:

**Process signatures** (in `init_process_sigs`):
```
%edr_process_signatures["processname.exe"] = "Vendor | Product Name | Category";
```

**Service signatures** (in `init_service_sigs`):
```
%edr_service_signatures["servicename"] = "Vendor | Product Name | Category";
```

Categories: `EDR`, `AV`, `EPP`, `Telemetry`, `SIEM-EDR`, `DFIR`, `Vuln Scanner`

## License

MIT

## Disclaimer

This tool is intended for authorized red team engagements and security testing only. Ensure you have proper authorization before use. The author assumes no liability for misuse.
