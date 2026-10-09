<p align="center">
  <img src="assets/nextvm-logo.png" alt="NEXTVM Logo" width="200" height="200" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Android-3DDC84?style=for-the-badge&logo=android&logoColor=white" />
  <img src="https://img.shields.io/badge/Language-Kotlin-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white" />
  <img src="https://img.shields.io/badge/NDK-C++-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" />
  <img src="https://img.shields.io/badge/Min%20SDK-26-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Target%20SDK-35-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Alpha-orange?style=for-the-badge" />
</p>

<h1 align="center">NEXTVM</h1>
<h3 align="center">Next-Generation Android Virtual Environment Engine</h3>

<p align="center">
  <strong>Run any Android app inside a fully isolated, sandboxed virtual environment — without root, without emulators, directly on your phone.</strong>
</p>

<p align="center">
  <a href="#architecture">Architecture</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#roadmap">Roadmap</a> &bull;
  <a href="#building">Building</a> &bull;
  <a href="#contributing">Contributing</a> &bull;
  <a href="#license">License</a>
</p>

---

## What is NEXTVM?

NEXTVM is a **lightweight Android virtualization engine** that creates isolated virtual environments on Android devices. Unlike traditional emulators that simulate hardware, NEXTVM uses **Binder proxy interception** and **ActivityThread hooking** to run real Android apps in a sandboxed process — achieving near-native performance with complete isolation.

Think of it as a "parallel universe" for your Android apps — each app runs with its own identity, storage, accounts, and network configuration, completely isolated from the host device and from each other.

### Why NEXTVM?

| Problem | NEXTVM Solution |
|---------|----------------|
| Testing apps without affecting your real data | Fully isolated sandbox with virtual filesystem |
| Running multiple accounts of the same app | Up to 10 independent instances, each with unique identity |
| Privacy concerns with untrusted apps | Apps see only what you allow — fake contacts, fake location, fake device identity |
| Security research & app analysis | Built-in runtime analysis tools, no root required |
| App compatibility testing across device profiles | Spoof any device model, Android version, carrier, screen config |

---

## Architecture

NEXTVM is built on a **multi-layer interception architecture** that intercepts Android's IPC mechanism (Binder) at the application level, without requiring any OS modifications or root access.

```
┌──────────────────────────────────────────────────────┐
│                    NEXTVM Engine                      │
│                                                      │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  Guest   │  │ Binder Proxy │  │  Android OS   │  │
│  │   App    │──│    Layer     │──│  (Unmodified) │  │
│  │          │  │              │  │               │  │
│  └──────────┘  └──────────────┘  └───────────────┘  │
│       │              │                    │          │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Virtual  │  │ ActivityThread│  │  Native Hook  │  │
│  │ Context  │  │  mH Hook     │  │  Engine (C++) │  │
│  │ Sandbox  │  │  (Code 159)  │  │  GOT/PLT Patch│  │
│  └──────────┘  └──────────────┘  └───────────────┘  │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │              Identity Spoofing                │    │
│  │  Build.* | IMEI | ANDROID_ID | MAC | Carrier │    │
│  └──────────────────────────────────────────────┘    │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │             Anti-Detection Engine             │    │
│  │  Root | Emulator | Xposed | Virtual Env Hide │    │
│  └──────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

### Core Mechanism

1. **Binder Proxy Interception** — `IActivityManager`, `IPackageManager`, and system service proxies intercept all app-to-system IPC calls
2. **ActivityThread.mH Hook** — Intercepts `EXECUTE_TRANSACTION` (code 159) to swap ClassLoaders and redirect Activity launches through stub components
3. **Virtual Context** — Custom `ContextWrapper` that redirects all file I/O, databases, SharedPreferences, and identity queries to the sandbox
4. **Native Hook Engine (C++)** — GOT/PLT patching for `libc` functions (`open`, `openat`, `stat`, `access`, `fopen`, `__system_property_get`) to enforce isolation at the native level
5. **200 Stub Components** — 10 process slots × 20 components each (Activities, Services, ContentProviders, BroadcastReceivers) pre-declared in the manifest

### Module Structure

```
NEXTVM/
├── app/                          # Application entry point & DI
├── core/
│   ├── virtualization/           # VM engine, process management, lifecycle
│   ├── hook/                     # Native (C++) + Java hooking, anti-detection, identity spoofing
│   ├── binder/                   # Binder proxy interception (AM, PM, SystemServices)
│   ├── sandbox/                  # File system isolation, virtual context
│   ├── services/                 # Virtual system services, GMS integration
│   ├── framework/                # Android framework parsing, package validation
│   ├── apk/                      # APK parsing & class loading
│   ├── model/                    # Data models (VirtualApp, DeviceProfile, ProcessSlot)
│   ├── common/                   # Reflection utilities, compatibility helpers
│   └── designsystem/             # Material 3 theme, design tokens
├── feature/
│   ├── launcher/                 # App grid launcher UI
│   ├── appmanager/               # APK install/uninstall management
│   ├── settings/                 # Engine configuration & debugging
│   └── filemanager/              # Virtual filesystem browser
└── gradle/                       # Version catalog & wrapper
```

---

## Features

### Currently Implemented

- **App Virtualization** — Run third-party Android APKs in isolated sandbox processes
- **Multi-Instance Support** — Up to 10 parallel app instances, each in its own process slot
- **Complete File System Isolation** — Virtual `/data/data/`, `/sdcard/` per instance with native-level enforcement
- **Identity Spoofing Engine** — Per-instance device fingerprinting: Build.MODEL, MANUFACTURER, FINGERPRINT, IMEI, ANDROID_ID, MAC address, carrier info — all deterministically generated
- **Anti-Detection System** — 3-level bypass for root detection, emulator detection, virtual environment detection, Xposed detection, and signature verification
- **GMS Integration** — Hybrid architecture bridging to the host's real Google Play Services for auth, FCM push notifications, and Play Store compatibility
- **Native Hook Engine** — C++ GOT/PLT patcher for libc-level file path redirection and system property spoofing
- **Modern UI** — Jetpack Compose with Material 3, featuring launcher grid, app manager, file browser, and settings
- **Hilt DI** — Clean architecture with dependency injection across all 15 modules

### Coming Soon — Roadmap

<details>
<summary><b>Privacy & Security</b></summary>

| Feature | Description |
|---------|-------------|
| **Witness Protection** | AI-generated fake contacts, photos, SMS — apps see realistic but completely fake user data |
| **Phantom Network** | Per-app DNS routing, carrier spoofing, and independent network identity |
| **Panic Button** | One-tap encrypted wipe of all virtual data, launcher disguise as calculator app |
| **Clipboard Firewall** | Prevent apps from reading sensitive clipboard content |
| **Acoustic Sandbox** | Microphone isolation with optional white noise injection |
| **Self-Destruct Protocol** | Remote wipe via push notification trigger |

</details>

<details>
<summary><b>Power User Tools</b></summary>

| Feature | Description |
|---------|-------------|
| **Time Prison** | Per-app time freezing — lock any app's clock to a specific date without affecting the system |
| **Speed Controller** | Adjust app execution speed (0.1x to 10x) for games and testing |
| **App X-Ray** | Real-time transparent overlay showing all API calls, network traffic, and permission usage live |
| **Puppet Master API** | Local REST API to programmatically control any virtual app from another device on your network |
| **Mimic Engine** | AI-powered behavior recording and replay with image recognition-based UI adaptation |
| **Ghost Notifications** | Unified notification hub across all instances with smart grouping and stealth mode |

</details>

<details>
<summary><b>Analysis & Research</b></summary>

| Feature | Description |
|---------|-------------|
| **App Genome Mapping** | Automatic SDK/library detection with de-obfuscation and family fingerprinting |
| **Vulnerability Radar** | Auto-discover security weaknesses during app runtime — zero expertise required |
| **Forensic Camera** | Record all app behavior (screen, network, file I/O, crypto) in a unified timeline |
| **Binary Diff Engine** | Compare app versions at the code level — see exactly what changed beyond "bug fixes" |
| **Runtime Inspector** | Point-and-click runtime state viewer — tap any UI element to inspect/modify live objects |
| **Sandbox Theater** | Create fake environments (slow network, low battery, different country) to test app behavior |

</details>

<details>
<summary><b>Automation & Integration</b></summary>

| Feature | Description |
|---------|-------------|
| **Tasker/IFTTT Integration** | Expose virtual app events as broadcast intents for automation workflows |
| **Automation Engine** | Embedded scripting (Lua/Python) for complex app automation scenarios |
| **State Teleportation** | Transfer running app state between devices via QR code scan — no re-login required |
| **App Chimera** | Transplant visual themes and UI features between apps at runtime |

</details>

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **Language** | Kotlin 2.0 + C++ (NDK) |
| **UI Framework** | Jetpack Compose + Material 3 |
| **Architecture** | MVI + Clean Architecture |
| **DI** | Hilt (Dagger) |
| **Build System** | Gradle 8.9 + Version Catalog |
| **Native Hooks** | Custom GOT/PLT patcher (C++) |
| **Java Hooks** | Reflection-based field modification |
| **Min SDK** | 26 (Android 8.0) |
| **Target SDK** | 35 (Android 15) |
| **Modules** | 15 (1 app + 10 core + 4 feature) |

---

## Building

### Prerequisites

- Android Studio Ladybug (2024.2.1) or later
- JDK 17
- Android SDK 35
- NDK 27.1.12297006
- CMake (for native hook module)

### Steps

```bash
# Clone the repository
git clone https://github.com/TanvirHossain2/NEXTVM.git
cd NEXTVM

# Build debug APK
./gradlew :app:assembleDebug

# Install on connected device
./gradlew :app:installDebug
```

> **Note:** The project is in active alpha development. Some modules may have compilation issues that are being actively resolved.

---

## Project Status

NEXTVM is currently in **alpha stage**. The core virtualization engine, sandbox isolation, and identity spoofing systems are functional. We're actively working on expanding app compatibility and building out the advanced feature set.

### What Works

- APK installation and launch in virtual environment
- File system isolation with native-level enforcement
- Per-instance identity generation (unique device fingerprint per clone)
- Anti-detection bypasses for common root/emulator checks
- Google Play Services integration (auth, FCM, Play Store)
- Modern Compose UI with app launcher, file browser, and settings

### What's In Progress

- Expanding app compatibility (targeting 95% of Play Store apps)
- WebView process isolation
- Camera and media API proxying
- Storage Access Framework (SAF) support
- Comprehensive test suite
- Performance optimization and memory management

### Known Limitations

- **Strong commercial packers (e.g. SecNeo / 爱加密)**: apps protected by
  these shells crash inside the guest shortly after the shell library
  loads (verified with China Unicom v13.0). The shell's integrity check
  still detects the virtual environment even though every
  process-identity surface now reports the guest identity — kernel comm
  and argv[0], `/proc` contents (maps / status / stat / cmdline),
  fd and task enumeration, and the framework bind data behind
  `ActivityThread.currentProcessName()`. Root-causing the remaining
  detection channel (suspected: the synthetic ClassLoader / DexFile
  object graph the shell's ART hooks inspect) is not currently planned.

---

## Contributing

NEXTVM is a complex systems-level project and contributions are welcome! Here's how you can help:

### Good First Issues

- Writing unit tests for core modules (currently at 0% coverage)
- Improving error handling and logging
- UI polish and animations
- Documentation for individual modules

### Advanced Contributions

- Android system service proxy implementations
- Native hook improvements (migrating to [bhook](https://github.com/nicklhw/bhook) for broader compatibility)
- App compatibility fixes for specific apps/frameworks
- Multi-process ClassLoader isolation improvements
- Performance profiling and optimization

### Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Read through the module structure — start with `core/model` to understand data types, then `core/virtualization/engine/VirtualEngine.kt` for the main orchestrator
4. Make your changes with clear commit messages
5. Submit a pull request with description of what changed and why

### Architecture Deep-Dive for Contributors

The critical code path for understanding how app virtualization works:

1. **`VirtualEngine.kt`** → `installApp()` and `launchApp()` — entry points
2. **`StubRegistry.kt`** → How 200 stub components get mapped to real app components
3. **`ActivityThreadHook.kt`** → The `EXECUTE_TRANSACTION` interception that makes everything work
4. **`ActivityManagerProxy.kt`** → How `startActivity/startService/bindService` calls get redirected
5. **`VirtualContext.kt`** → How file I/O and identity queries get sandboxed
6. **`native-hook.cpp`** → The C++ GOT/PLT patcher that enforces isolation at the native layer

---

## How It Compares

| Feature | NEXTVM | VirtualApp | Parallel Space | Shelter |
|---------|--------|-----------|---------------|---------|
| No Root Required | Yes | Yes | Yes | Yes |
| Multi-Instance | 10 slots | Limited | 2 | Work Profile |
| Per-Instance Identity | Full spoof | Basic | None | None |
| Native-Level Isolation | GOT/PLT hooks | Yes | No | No |
| Anti-Detection | 3-level system | Basic | None | None |
| GMS Integration | Hybrid bridge | Full copy | Basic | System |
| Modern UI (Compose) | Yes | No | No | No |
| Open Source | Yes | Partial | No | Yes |
| Active Development | Yes | Abandoned | Closed | Minimal |
| Target Compatibility | 95% goal | ~70% | ~60% | Work Profile |

---

## Disclaimer

NEXTVM is designed for legitimate use cases including:

- **Privacy protection** — Run untrusted apps in isolation
- **App testing** — Test apps across different device configurations
- **Security research** — Analyze app behavior in a controlled environment
- **Multi-account management** — Run multiple instances of messaging and social apps
- **Development** — Test your own apps with different device profiles

Users are responsible for complying with applicable laws and terms of service when using this software. NEXTVM does not encourage or condone any form of software piracy, unauthorized access, or violation of third-party terms of service.

---

## License

```
Copyright 2024-2026 Tanvir Hossain

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

<p align="center">
  <b>Built with determination from Bangladesh</b>
  <br><br>
  <a href="https://github.com/TanvirHossain2/NEXTVM/stargazers">Star this repo</a> if you believe in the vision.
  <br>
  Let's build the most powerful Android virtual environment — together.
</p>
