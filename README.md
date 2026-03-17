# 🔐 RF Key Fob Security Research — 433 MHz Replay Attack Analysis

<div align="center">

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-433MHz-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)

**A comprehensive security research toolkit for automotive RF key fob vulnerability analysis, replay attack demonstration, and defense mechanism development.**

[Quick Start](#-quick-start) • [Tools](#-tools--features) • [Chip Analysis](#-chip-family-analysis) • [Vulnerabilities](#-vulnerabilities--risks) • [Defenses](#-defense-mechanisms)

</div>

---

## 📋 Table of Contents

1. [Overview](#-overview)
2. [Attack Surface](#-attack-surface)
3. [Quick Start](#-quick-start)
4. [Installation](#-installation)
5. [Tools & Features](#-tools--features)
6. [Chip Family Analysis](#-chip-family-analysis)
7. [Vulnerabilities & Risks](#-vulnerabilities--risks)
8. [Defense Mechanisms](#-defense-mechanisms)
9. [References](#-references)
10. [Ethical Disclaimer](#-ethical-disclaimer)
11. [License](#-license)

---

## 🎯 Overview

This project provides a complete framework for understanding, analyzing, and demonstrating security vulnerabilities in automotive RF key fobs operating at 433 MHz. It covers the entire attack chain — from signal capture and demodulation through to replay attack execution and defense detection.

**Key Research Areas:**
- 🛰️ **OOK Demodulation** — On-Off Keying signal processing and frame detection
- 🔄 **Fixed vs Rolling Code** — Comparative vulnerability analysis
- 🎮 **Replay Attack Demonstration** — Real-world attack scenarios
- 🛡️ **Defense & Detection** — Jamming and replay detection monitoring
- 🔬 **Chip Family Classification** — PT2262, EV1527, KeeLoq, and AUT64 analysis

**Why This Matters:**
Modern automotive security is critical infrastructure. Understanding key fob vulnerabilities helps manufacturers patch systems and allows researchers to identify zero-days before malicious actors do.

---

## 🗺️ Attack Surface

```
┌─────────────────────────────────────────────────────────────┐
│                    433 MHz RF Key Fob                        │
│                   Transmitter Circuit                        │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐    ┌─────▼─────┐   ┌────▼─────┐
    │  Encode │    │  Modulate │   │ Transmit │
    │ (Code)  │    │  (OOK)    │   │(433 MHz) │
    └────┬────┘    └─────┬─────┘   └────┬─────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
          ▼──────────────▼──────────────▼
     ┌──────────────────────────────────┐
     │  VULNERABILITY WINDOW 🚨          │
     │  ├─ Unencrypted transmission      │
     │  ├─ Fixed code (no rolling)       │
     │  ├─ Predictable timing            │
     │  ├─ Weak encoding (PT2262)        │
     │  └─ Replay attack vector          │
     └──────────────────────────────────┘
          ▲──────────────┬──────────────▲
         │               │               │
    ┌────▼────┐    ┌─────▼─────┐   ┌────▼─────┐
    │ Receive │    │ Demodulate│   │ Decode   │
    │ (SDR)   │    │ (OOK)     │   │ (Frame)  │
    └────┬────┘    └─────┬─────┘   └────┬─────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
                    ┌────▼─────┐
                    │ Actuator │
                    │  (Unlock)│
                    └──────────┘
```

---

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/wincr4ck/rf-keyfob-research.git
cd rf-keyfob-research

# Install dependencies
pip install -r requirements.txt

# Run in simulation mode (no hardware needed)
python3 capture.py --simulate --duration 2 --output signal.iq
python3 analyzer.py --input signal.iq --family PT2262
python3 defense.py --monitor --simulate

# Or with real hardware (RTL-SDR/HackRF)
python3 capture.py --sdr rtlsdr --frequency 433.92e6 --duration 10
python3 replay.py --input captured.iq --sdr hackrf --frequency 433.92e6
```

---

## 📦 Installation

### Requirements

- **Python 3.8+**
- **pip** (Python package manager)
- **Optional Hardware:** RTL-SDR or HackRF for real signal capture and replay

### Step-by-Step Setup

```bash
# 1. Clone repository
git clone https://github.com/wincr4ck/rf-keyfob-research.git
cd rf-keyfob-research

# 2. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python3 capture.py --help
python3 analyzer.py --help
python3 replay.py --help
python3 defense.py --help
```

### Dependencies (`requirements.txt`)

```
numpy>=1.21.0
scipy>=1.7.0
matplotlib>=3.4.0
rtlsdr>=0.2.8
pyusb>=1.2.1
pysimplesoap>=1.16.2
hackrf>=0.1.0
```

---

## 🛠️ Tools & Features

### 1. 📡 `capture.py` — IQ Capture & OOK Demodulation

Captures raw RF signals and performs OOK (On-Off Keying) demodulation to extract the modulated code.

**Features:**
- Real-time IQ sample capture from RTL-SDR or HackRF
- Automatic frequency detection (433.05–433.92 MHz)
- OOK demodulation with configurable thresholds
- Frame detection and synchronization
- Simulation mode for testing without hardware

**CLI Flags:**
```bash
python3 capture.py [OPTIONS]

OPTIONS:
  --sdr {rtlsdr,hackrf,simulate}  SDR type (default: simulate)
  --frequency FREQ                Capture frequency in Hz (default: 433.92e6)
  --duration SECONDS              Capture duration (default: 5)
  --sample-rate RATE              Sample rate in S/s (default: 2e6)
  --threshold FLOAT               OOK threshold 0-1 (default: 0.5)
  --output FILE                   Output IQ file (default: signal.iq)
  --simulate                      Use simulation mode
  --verbose                       Enable verbose logging
```

**Example Usage:**
```bash
# Capture 10 seconds with RTL-SDR
python3 capture.py --sdr rtlsdr --frequency 433.92e6 --duration 10 --output capture1.iq

# Simulate capture without hardware
python3 capture.py --simulate --duration 2 --threshold 0.5 --output sim_signal.iq

# High sample rate for detailed analysis
python3 capture.py --sdr hackrf --sample-rate 10e6 --duration 5 --verbose
```

---

### 2. 🎮 `replay.py` — Replay Attack Implementation

Replays captured RF signals to demonstrate the vulnerability. This is the core attack demonstration tool.

**Features:**
- Playback of captured IQ signals
- Real-time transmission via HackRF or RTL-SDR (transmit mode)
- Timing control and burst repetition
- Frequency accuracy calibration
- Frame-by-frame replay with configurable delay

**CLI Flags:**
```bash
python3 replay.py [OPTIONS]

OPTIONS:
  --input FILE                    Input IQ file (required)
  --sdr {hackrf,rtlsdr}           SDR device (default: hackrf)
  --frequency FREQ                Transmit frequency in Hz (default: 433.92e6)
  --gain GAIN                     TX gain 0-47 (default: 10)
  --repeat COUNT                  Number of repeats (default: 5)
  --delay SECONDS                 Delay between repeats (default: 0.5)
  --calibrate                     Enable frequency calibration
  --dry-run                       Simulate without transmitting
  --verbose                       Enable verbose logging
```

**Example Usage:**
```bash
# Basic replay (5 times)
python3 replay.py --input capture1.iq --sdr hackrf --repeat 5

# Dry run to test without transmitting
python3 replay.py --input capture1.iq --dry-run --verbose

# Calibrated replay with frequency correction
python3 replay.py --input capture1.iq --calibrate --gain 15
```

---

### 3. 🔬 `analyzer.py` — Chip Family Detection & Analysis

Analyzes captured signals to identify the encoding chip family and extract vulnerability details.

**Features:**
- Automatic chip family classification (PT2262, EV1527, KeeLoq, AUT64)
- Protocol pattern recognition
- Code extraction and analysis
- Bit rate and timing analysis
- Vulnerability assessment per family

**CLI Flags:**
```bash
python3 analyzer.py [OPTIONS]

OPTIONS:
  --input FILE                    Input IQ file (required)
  --family {PT2262,EV1527,KeeLoq,AUT64,auto}  Chip family (default: auto)
  --threshold FLOAT               Demodulation threshold 0-1 (default: 0.5)
  --extract-code                  Extract and display raw code
  --timing-analysis               Perform detailed timing analysis
  --output FILE                   Save analysis to JSON file
  --verbose                       Enable verbose logging
```

**Example Usage:**
```bash
# Auto-detect chip family
python3 analyzer.py --input signal.iq --family auto --verbose

# Analyze as PT2262 with code extraction
python3 analyzer.py --input signal.iq --family PT2262 --extract-code --output analysis.json

# Timing analysis for rolling code detection
python3 analyzer.py --input signal.iq --timing-analysis --output timing.json
```

---

### 4. 🛡️ `defense.py` — Replay & Jamming Detection Monitor

Monitors for and detects replay attacks and jamming attempts on key fob systems.

**Features:**
- Real-time signal monitoring (RTL-SDR compatible)
- Replay attack pattern detection
- Jamming signal detection
- Statistical anomaly analysis
- Alert system with configurable thresholds
- Simulation mode for testing

**CLI Flags:**
```bash
python3 defense.py [OPTIONS]

OPTIONS:
  --sdr {rtlsdr,simulate}         SDR type (default: simulate)
  --frequency FREQ                Monitor frequency in Hz (default: 433.92e6)
  --duration SECONDS              Monitoring duration (default: 60)
  --sample-rate RATE              Sample rate in S/s (default: 2e6)
  --replay-threshold FLOAT        Replay detection threshold 0-1 (default: 0.8)
  --jam-threshold FLOAT           Jamming threshold 0-1 (default: 0.7)
  --monitor                       Continuous monitoring mode
  --alert-file FILE               Save alerts to file
  --verbose                       Enable verbose logging
  --simulate                      Use simulation mode
```

**Example Usage:**
```bash
# Monitor for attacks (simulation)
python3 defense.py --monitor --simulate --duration 120 --verbose

# Real monitoring with RTL-SDR
python3 defense.py --sdr rtlsdr --monitor --duration 300 --alert-file alerts.log

# Save detailed alerts
python3 defense.py --monitor --simulate --alert-file security_alerts.json --verbose
```

---

## 📊 Chip Family Analysis

| Feature | PT2262 | EV1527 | KeeLoq (HCS301) | AUT64 |
|---------|--------|--------|-----------------|-------|
| **Encoding Type** | Fixed Code | Rolling Code | Hopping Code | Advanced |
| **Bit Length** | 12 bits | 25 bits | 66 bits | 64+ bits |
| **Vulnerability** | 🔴 CRITICAL | 🟡 MEDIUM | 🟡 MEDIUM | 🟢 SECURE |
| **Replay Attack** | ✅ Vulnerable | ⚠️ Limited | ⚠️ Limited | ❌ Resistant |
| **Brute Force** | ✅ Feasible | ❌ Infeasible | ❌ Infeasible | ❌ Infeasible |
| **Known Exploits** | Multiple | Research Only | RollJam | None Public |
| **CWE-294 Risk** | 🔴 CRITICAL | 🟡 MEDIUM | 🟡 MEDIUM | 🟢 LOW |
| **CVSS Score** | 9.1 CRITICAL | 6.2 MEDIUM | 7.5 HIGH | 2.1 LOW |
| **Common In** | Older cars (pre-2010) | Mid-range cars | Premium vehicles | Modern EVs |
| **Real-World Affected** | VW, Hyundai, Nissan | Toyota, Ford | BMW, Mercedes | Tesla, Lucid |

### Chip Details

**PT2262** — Highly Vulnerable. Uses a static 12-bit code with no rolling code mechanism, making it directly susceptible to replay attacks. Brute force is feasible across all 4,096 possible codes. Classified as CWE-294 (Authentication Bypass by Capture-replay).

**EV1527** — Medium Risk. Implements a rolling code with a 25-bit sequence, providing stronger protection than PT2262, but a vulnerability window exists with multiple replay captures under certain conditions.

**KeeLoq / HCS301** — Medium Risk. Uses a hopping code based on the KEELOQ algorithm but is vulnerable to the RollJam attack demonstrated by Samy Kamkar at DEF CON 2015. Requires synchronization between transmitter and receiver, which can be deliberately disrupted.

**AUT64** — Modern Secure Implementation. Uses advanced encryption with 64-bit rolling codes and multiple authentication layers. Currently considered best practice for automotive implementations.

---

## ⚠️ Vulnerabilities & Risks

### CWE-294: Authentication Bypass by Capture-replay

**CVSS v3.1 Score: 8.1 (HIGH)**

**Affected:** PT2262, EV1527 with weak implementation

**Description:** RF key fobs using fixed codes or predictable rolling codes allow an attacker to capture a valid transmission and replay it to trigger vehicle unlock or ignition without holding the physical key.

**CVSS Metrics:**
- **Attack Vector:** Physical proximity (~100 meter RF range)
- **Attack Complexity:** Low (direct replay)
- **Privileges Required:** None
- **User Interaction:** None
- **Confidentiality Impact:** Low
- **Integrity Impact:** High (vehicle control)
- **Availability Impact:** High (vehicle immobilized)

### Real-World Attack Patterns

**RollJam Attack (Samy Kamkar, DEF CON 2015)**
```
1. Attacker deploys two SDR devices near the target vehicle.
2. Device A jams the 433 MHz channel to prevent the car from receiving.
3. Device B captures the fob's transmission during the jam.
4. Device A replays the captured frame at high power — vehicle unlocks.
5. The receiver never advanced its rolling code counter.
6. The attacker now holds a valid future code for later use.
```

**Fixed-Code Keylog Attack**
```
- Capture multiple transmissions from the target fob.
- Build a local database of valid codes.
- Replay any captured code at will.
- Particularly effective against PT2262 devices.
```

---

## 🛡️ Defense Mechanisms

### Detection Strategies in `defense.py`

**Replay Attack Detection** works by performing statistical analysis of inter-frame timing, detecting duplicate frames within short intervals, and validating sequence numbers and HMAC signatures where supported.

**Jamming Detection** looks for power level anomalies, noise floor elevation, signal quality degradation, and bandwidth expansion on the monitored frequency.

**Rolling Code Monitoring** tracks expected sequence numbers, raises alerts for out-of-order packets, and detects sync loss between the transmitter and receiver.

**Anomaly Detection** continuously monitors for timing pattern irregularities, frequency drift, power envelope changes, and elevated bit error rates.

### Recommended Defenses

**For Manufacturers:**
- Implement rolling codes (KeeLoq minimum, AUT64 preferred)
- Add HMAC/signature verification to all transmissions
- Combine frequency hopping with code hopping
- Implement strict receive-window timeouts
- Add active jamming detection on the receiver side
- Require firmware validation before unlock authorization

**For Vehicle Owners:**
- Store key fobs in a Faraday pouch when not in use
- Enable the steering wheel lock as a secondary deterrent
- Park in secure, monitored garages where possible
- Enable GPS tracking and tamper alerts if available

---

## 📚 References

1. **Samy Kamkar — RollJam: Remote Power/RF Control Jam & Replay** — DEF CON 23, 2015. https://samy.pl/rolljam/

2. **Garcia, F. D.; Oswald, D.; Kasper, T.; Pavlidès, P.** — *Lock It and Still Lose It — On the (In)Security of Automotive Remote Keyless Systems*, USENIX Security 2016. https://eprint.iacr.org/2012/450.pdf

3. **Eisenbarth, T.; Kasper, T.; et al.** — *On the Implementation of the Advanced Encryption Standard on FPGA*, 2007.

### Tools & Frameworks Referenced
- **GNU Radio** — RF signal processing framework
- **RTL-SDR / HackRF** — Software-defined radio hardware platforms
- **URH (Universal Radio Hacker)** — Visual RF signal analysis tool
- **Wireshark + RF plugins** — Protocol-level analysis

### Standards
- **ISM Band 433 MHz** — License-free frequency band specification
- **OOK Modulation** — On-Off Keying standard
- **NIST SP 800-38A** — Block Cipher Modes of Operation

---

## ✅ Ethical & Legal Disclaimer

> ⚠️ This project is provided **for educational and authorized security research purposes only**.

**Permitted Use:**
- Academic research on equipment you own
- Authorized penetration testing of systems you have written permission to test
- Manufacturer security validation and bug bounty programs
- Government or law enforcement activities with appropriate authorization

**Prohibited Use:**
- Unauthorized access to any vehicle or system
- Jamming licensed frequencies (illegal in most jurisdictions)
- Eavesdropping on third-party communications
- Vehicle theft or unauthorized unlock of any kind
- Interference with emergency or safety-critical frequencies

**Jurisdiction Notes:**
- 🇺🇸 USA — FCC Title 47, Computer Fraud and Abuse Act (CFAA)
- 🇪🇺 EU — Radio Equipment Directive (RED), GDPR
- 🇱🇰 Sri Lanka — Telecommunications Regulatory Commission (TRCSL)
- Check local wireless regulations before operating any RF hardware.

**Responsible Disclosure:** If you discover a vulnerability in an automotive key fob system, report it directly to the vehicle manufacturer through their coordinated disclosure program (HackerOne, Bugcrowd, or Intigriti). Allow a minimum 90-day remediation window before any public disclosure, and do not demonstrate attacks on vehicles you do not own.

By using this toolkit you agree to use it solely for lawful, authorized purposes and to comply with all applicable regulations.

---

## 📄 License

This project is licensed under the **MIT License** — see the `LICENSE` file for full details.

---

<div align="center">

*Made for the security research community. If this helped your work, a ⭐ is appreciated.*

</div>
