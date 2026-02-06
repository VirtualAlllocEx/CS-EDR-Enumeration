# CS-EDR-Enumeration

Cobalt Strike Aggressor Script for enumerating AV, EPP, EDR, and Telemetry/SIEM products on compromised Windows hosts. Provides **six enumeration commands** with different noise footprints, letting operators choose the method that fits their current risk tolerance.

![Cobalt Strike](https://img.shields.io/badge/Cobalt%20Strike-4.x-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Signatures](https://img.shields.io/badge/Signatures-447-blue)
![Vendors](https://img.shields.io/badge/Vendors-48-orange)

## Why This Exists

Knowing what security products are running on a host is the first question after initial access. The problem: most enumeration techniques spawn `powershell.exe` or `cmd.exe`, generating telemetry that the very EDR you're trying to identify will flag. The irony of spawning the most-monitored process on the system to ask whether the system is monitored shouldn't be lost on anyone.

This script provides a graduated approach — from completely silent (in-process BOF, zero artifacts) to full WMI enumeration — so operators can make informed decisions about detection tradeoffs.

## Features

- **199 process**, **115 service**, and **133 driver signatures** covering **48 security vendors**
- **Kernel driver enumeration** — detects EDR minifilters and callbacks even when user-mode services are stopped
- **Six commands** sorted by noise level from `★` (silent) to `★★★★` (loud)
- **BOF with mode selection** — enumerate services only, drivers only, or both
- Inline BOF execution — zero child processes, no AMSI/CLR/ETW
- Automatic threat level assessment (HIGH / MODERATE / LOW)
- Color-coded output by product category: `[EDR]` `[AV]` `[EPP]` `[TEL]` `[DRV]`
- Built-in `edr_help` with split artifact/coverage matrices

## Supported Vendors

| Category | Vendors |
|----------|---------|
| **EDR** | CrowdStrike, SentinelOne, Carbon Black, Microsoft Defender for Endpoint, Cortex XDR, Elastic Security, Sophos Intercept X, Trend Micro Apex One, Trellix/FireEye, ESET Inspect, Bitdefender GravityZone, Cybereason, Fortinet FortiEDR, HarfangLab, Huntress, Deep Instinct, LimaCharlie, Rapid7, Tanium, Dell Secureworks, Endgame |
| **AV** | Microsoft Defender, ESET, Kaspersky, Sophos, McAfee/Trellix, Trend Micro, Bitdefender, Webroot, Malwarebytes, WithSecure/F-Secure, Avast/AVG, Avira, Norton/Gen Digital, Comodo/Xcitium, G Data, Emsisoft, Dr.Web, AhnLab, VIPRE/ThreatTrack |
| **EPP** | Broadcom/Symantec, BlackBerry Cylance, WatchGuard/Panda, Check Point Harmony |
| **Telemetry/SIEM** | Sysmon, Splunk UF, Elastic Beats, Wazuh/OSSEC, Velociraptor, Nexthink |
| **ZTNA/Other** | Zscaler, CyberArk, Cisco Secure Endpoint, Qualys |

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

### BOF Modes

`edr_services_bof` accepts an optional argument to control enumeration scope:

| Command | Scope | Use Case |
|---------|-------|----------|
| `edr_services_bof` | Services + drivers | Full picture (default) |
| `edr_services_bof svc` | Services only | Quick vendor ID, less output over slow C2 |
| `edr_services_bof drv` | Drivers only | Verify kernel callbacks after service kill |

One compiled BOF, one `inline-execute` call. The operator picks scope at runtime.

### Recommended Workflow

```
1. edr_check                ★     Always. Zero cost.
2. edr_services_bof         ★     If BOF is compiled. Zero cost.
   edr_services_bof svc     ★     Quick vendor ID only.
   edr_services_bof drv     ★     Drivers only (post-svc-kill check).
3. edr_services_pick        ★★    If CLR loading is acceptable.
4. edr_services_cmd         ★★★   If cmd.exe child is acceptable.
5. edr_services              ★★★★  Only if PowerShell is already expected.
6. edr_enum                 ★★★★  Full picture, highest artifact cost.
```

**Best combo:** `edr_check` + `edr_services_bof` = full process, service, AND kernel driver visibility at noise level ★ with zero extra artifacts.

**Post-exploit:** After killing an EDR service, run `edr_services_bof drv` to verify whether kernel callbacks and minifilters are still loaded.

### Artifact Matrix (Detection Surface)

What each command leaves behind — fewer marks is better:

```
                    check  bof   bof   bof   pick  cmd   svc   enum
                           both  svc   drv
Child Process:      -      -     -     -     -     cmd   PS    PS
CLR Loading:        -      -     -     -     YES   -     YES   YES
AMSI:               -      -     -     -     YES   -     YES   YES
ScriptBlock:        -      -     -     -     -     -     YES   YES
Module Log:         -      -     -     -     -     -     YES   YES
Transcript:         -      -     -     -     -     -     poss  poss
WMI Log:            -      -     -     -     -     -     -     YES
Sysmon EID 1:       -      -     -     -     -     YES   YES   YES
Sysmon EID 7:       -      -     -     -     YES   -     -     -
.NET ETW:           -      -     -     -     YES   -     -     -
EID 4688:           -      -     -     -     -     YES   YES   YES
```

### Coverage Matrix (What You Get Back)

What intel each command returns:

```
                    check  bof   bof   bof   pick  cmd   svc   enum
                           both  svc   drv
Processes:          YES    -     -     -     -     -     -     YES
Services:           -      YES   YES   -     YES   YES   YES   YES
Kernel Drivers:     -      YES   -     YES   -     -     -     -
WMI AV Products:    -      -     -     -     -     -     -     YES
```

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
x86_64-w64-mingw32-gcc -c svc_enum_bof.c -o svc_enum_bof.x64.o

# x86
i686-w64-mingw32-gcc -c svc_enum_bof.c -o svc_enum_bof.x86.o
```

Place the compiled `.o` files in the **same directory** as `edr-enum.cna`.

> **Note:** The `.o` filenames must use dot convention (`svc_enum_bof.x64.o`, not `svc_enum_bof_x64.o`) to match the CNA's `script_resource()` lookup.

## File Structure

```
CS-EDR-Enumeration/
├── edr-enum.cna          # Aggressor Script (main script)
├── svc_enum_bof.c        # BOF source for service + driver enumeration
├── beacon.h              # Cobalt Strike BOF API header
├── Makefile              # Cross-compilation build script
└── README.md
```

## Output Examples

### Process-Based Enumeration (`edr_check`)

Uses Beacon's native `bps()` — no child process, no DLL loads, no ETW. Zero artifacts.

<p align="center">
  <img width="700" alt="edr_check process enumeration output" src="https://github.com/user-attachments/assets/aa2f00ae-74aa-4db0-ae3a-f4762ab36e13" />
</p>

### BOF Service + Driver Enumeration (`edr_services_bof`)

In-process enumeration via `OpenSCManagerW` + `EnumServicesStatusExW`. Enumerates both Win32 services and kernel drivers. Same noise level as `edr_check`.

<p align="center">
  <img width="700" alt="edr_services_bof service and driver enumeration output" src="https://github.com/user-attachments/assets/2da8c8cf-fa08-4f1b-99bf-a3b6f3199575" />
</p>

### Other Methods

<details>
<summary>bpowerpick — Unmanaged PowerShell (★★)</summary>

<p align="center">
  <img width="700" alt="edr_services_pick unmanaged PowerShell output" src="https://github.com/user-attachments/assets/7ebd8eec-c7b3-4da8-b9ca-8694e272d2f5" />
</p>

Loads CLR into Beacon process. No `powershell.exe` child, but EDRs may flag unmanaged CLR hosting.
</details>

<details>
<summary>bpowershell — PowerShell Get-Service (★★★★)</summary>

<p align="center">
  <img width="700" alt="edr_services PowerShell Get-Service output" src="https://github.com/user-attachments/assets/d8075abc-67b3-4e2c-b28e-f28d0bbc699f" />
</p>

Spawns `powershell.exe` — activates ScriptBlock logging, Module logging, AMSI, and process creation events.
</details>

<details>
<summary>bshell — cmd.exe sc query (★★★)</summary>

<p align="center">
  <img width="700" alt="edr_services_cmd sc query output" src="https://github.com/user-attachments/assets/5ded11af-71c8-4606-bb89-b3c0437ce0f8" />
</p>

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

The BOF (`svc_enum_bof.c`) performs two-phase enumeration via the Service Control Manager API:

1. **Phase 1 — Win32 Services** (`SERVICE_WIN32`): User-mode services, output as `SERVICE_NAME:` lines
2. **Phase 2 — Kernel Drivers** (`SERVICE_DRIVER`): Kernel, file system, and recognizer drivers, output as `DRIVER_NAME:` lines

Both phases share a single `SCManager` handle and output in one contiguous blob. The mode argument (packed short: 0=both, 1=svc, 2=drv) controls which phases execute.

Technical specifics:
- Opens `SCManager` with `SC_MANAGER_ENUMERATE_SERVICE`
- Calls `EnumServicesStatusExW` with two-call pattern (size query → allocate → enumerate)
- Converts wide service names to narrow (UTF-8) for signature matching
- All API calls use Dynamic Function Resolution (DFR) — no static imports, no IAT entries
- Single 512 KB format buffer accommodates systems with 300+ services and 200+ drivers

## Threat Levels

| Level | Meaning | Implications |
|-------|---------|--------------|
| **HIGH** | Active EDR detected | Kernel callbacks, user-mode hooks, ETW TI, cloud analytics, tamper protection |
| **MODERATE** | AV + Telemetry | File scanning + event forwarding to SOC |
| **LOW-MOD** | AV only | File scanning, heuristics, AMSI |
| **LOW** | Non-EDR/AV only | EPP, vulnerability scanner, minimal real-time |
| **UNKNOWN** | Nothing detected | May be kernel-only, agentless, cloud-native, or NDR |

## Contributing

PRs welcome for new vendor signatures. The format is straightforward:

**Process signatures** (in `init_process_sigs`):
```sleep
%edr_process_signatures["processname.exe"] = "Vendor | Product Name | Category";
```

**Service signatures** (in `init_service_sigs`):
```sleep
%edr_service_signatures["servicename"] = "Vendor | Product Name | Category";
```

**Driver signatures** (in `init_driver_sigs`):
```sleep
%edr_driver_signatures["drivername"] = "Vendor | Product Name | Category";
```

Categories: `EDR`, `AV`, `EPP`, `Telemetry`, `SIEM-EDR`, `DFIR`, `ZTNA`, `Vuln Scanner`

> **Note:** All signature keys must be lowercase. Matching uses substring comparison (`isin`) against extracted names, so short keys (< 5 chars) risk false positives against unrelated Windows services. When in doubt, prefer longer, more specific keys.

## License

MIT

## Disclaimer

This tool is intended for authorized red team engagements and security testing only. Ensure you have proper authorization before use. The author assumes no liability for misuse.
