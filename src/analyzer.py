#!/usr/bin/env python3
"""
RF Signal Analyzer — Fixed Code vs Rolling Code Classifier
============================================================
Author  : Usal Winodith (wincr4ck)
Research: Automotive Key Fob RF Security @ 433 MHz

Description:
    Deep analysis of captured key fob signals.
    Classifies encoding type, estimates chip family,
    calculates vulnerability score, and generates
    a full technical report.

Supported Chip Families:
    - PT2262 / PT2272  (fixed code, 24-bit, tri-state)
    - EV1527 / HS1527  (fixed code, 24-bit OOK)
    - HCS301 / KeeLoq  (rolling code, 66-bit)
    - AUT64            (rolling code, automotive)
    - Generic OOK      (unknown fixed or rolling)
"""

import numpy as np
import json
import argparse
import os
from collections import Counter
from capture import (
    load_capture, iq_to_amplitude, normalize_amplitude,
    ook_demodulate, extract_pulses, pulses_to_bits,
    detect_preamble, bits_to_hex, calculate_entropy,
    simulate_capture, SAMPLE_RATE, PULSE_UNIT_US
)


# ─────────────────────────────────────────────────
#  CHIP FAMILY SIGNATURES
# ─────────────────────────────────────────────────

CHIP_SIGNATURES = {
    "PT2262": {
        "bit_length"    : 24,
        "encoding"      : "tri-state OOK",
        "repeat_count"  : (3, 12),
        "pulse_ratio"   : (1, 3),      # Short:Long pulse ratio
        "entropy_range" : (0.3, 0.75),
        "vulnerable"    : True,
        "attack"        : "Basic Replay",
        "description"   : "Princeton PT2262 — 24-bit fixed code, tri-state encoding. "
                          "Extremely common in garage doors, gate remotes, cheap car alarms. "
                          "Fully vulnerable to replay attack."
    },
    "EV1527": {
        "bit_length"    : 24,
        "encoding"      : "OOK",
        "repeat_count"  : (3, 8),
        "pulse_ratio"   : (1, 3),
        "entropy_range" : (0.4, 0.80),
        "vulnerable"    : True,
        "attack"        : "Basic Replay",
        "description"   : "EV1527 / HS1527 — 20-bit address + 4-bit data, fixed OOK. "
                          "Widely used in Chinese RF remotes, cheap car alarms, smart home devices. "
                          "Fully vulnerable to replay attack."
    },
    "HCS301_KEELOQ": {
        "bit_length"    : 66,
        "encoding"      : "KeeLoq rolling code",
        "repeat_count"  : (2, 4),
        "pulse_ratio"   : (1, 2),
        "entropy_range" : (0.85, 1.0),
        "vulnerable"    : False,
        "attack"        : "RollJam (Samy Kamkar, DEF CON 2015)",
        "description"   : "Microchip HCS301 KeeLoq — 32-bit encrypted rolling code + 34-bit fixed. "
                          "Used in OEM automotive remotes (GM, Chrysler, etc). "
                          "NOT vulnerable to basic replay. Vulnerable to RollJam attack."
    },
    "AUT64": {
        "bit_length"    : 64,
        "encoding"      : "AUT64 rolling code",
        "repeat_count"  : (2, 3),
        "pulse_ratio"   : (1, 2),
        "entropy_range" : (0.88, 1.0),
        "vulnerable"    : False,
        "attack"        : "Cryptanalysis required",
        "description"   : "AUT64 — 64-bit rolling code used in European automotive. "
                          "Strong cryptographic protection. Not practically vulnerable."
    }
}


# ─────────────────────────────────────────────────
#  ADVANCED ANALYSIS
# ─────────────────────────────────────────────────

def detect_tri_state_encoding(bit_string: str) -> bool:
    """
    Detect tri-state encoding used by PT2262.
    In tri-state, each logical bit is encoded as 2 physical bits:
      '0' → short pulse + long gap  (10)
      '1' → long pulse + short gap  (110 or similar)
      'F' → short pulse + short gap (1100)
    """
    # Check if pattern has groups of 2 or 4 bits
    chunks_of_2 = [bit_string[i:i+2] for i in range(0, len(bit_string)-1, 2)]
    valid_pairs = {'10', '01', '11', '00'}
    ratio = sum(1 for c in chunks_of_2 if c in valid_pairs) / max(len(chunks_of_2), 1)
    return ratio > 0.8


def detect_manchester_encoding(bit_string: str) -> bool:
    """
    Detect Manchester encoding (each bit = transition).
    '1' = 01, '0' = 10 in IEEE 802.3 Manchester.
    """
    if len(bit_string) < 16:
        return False
    transitions = sum(1 for i in range(len(bit_string)-1)
                      if bit_string[i] != bit_string[i+1])
    transition_rate = transitions / (len(bit_string) - 1)
    return transition_rate > 0.7


def analyze_pulse_timing(pulses: list) -> dict:
    """
    Analyze pulse timing statistics.
    Returns pulse duration distribution and ratio analysis.
    """
    if not pulses:
        return {}

    durations_1 = [d for v, d in pulses if v == 1]
    durations_0 = [d for v, d in pulses if v == 0]

    result = {
        "total_pulses"     : len(pulses),
        "high_pulse_count" : len(durations_1),
        "low_pulse_count"  : len(durations_0),
    }

    if durations_1:
        result["high_pulse_avg_us"] = round(np.mean(durations_1), 1)
        result["high_pulse_min_us"] = round(np.min(durations_1), 1)
        result["high_pulse_max_us"] = round(np.max(durations_1), 1)

    if durations_0:
        result["low_pulse_avg_us"]  = round(np.mean(durations_0), 1)
        result["low_pulse_min_us"]  = round(np.min(durations_0), 1)
        result["low_pulse_max_us"]  = round(np.max(durations_0), 1)

    if durations_1 and durations_0:
        short = min(np.mean(durations_1), np.mean(durations_0))
        long  = max(np.mean(durations_1), np.mean(durations_0))
        result["pulse_ratio"] = round(long / short, 2) if short > 0 else 0

    return result


def match_chip_family(bit_string: str, pulses: list, entropy: float) -> tuple:
    """
    Match signal characteristics to known chip families.

    Returns:
        tuple: (chip_name, confidence_percent, chip_info_dict)
    """
    best_match  = "UNKNOWN"
    best_conf   = 0
    best_info   = {}

    bit_len     = len(bit_string)
    timing      = analyze_pulse_timing(pulses)
    pulse_ratio = timing.get("pulse_ratio", 0)

    for chip_name, sig in CHIP_SIGNATURES.items():
        confidence = 0

        # Bit length match
        target_len = sig["bit_length"]
        if abs(bit_len - target_len) <= 4:
            confidence += 40
        elif abs(bit_len - target_len) <= 10:
            confidence += 20

        # Entropy range match
        e_min, e_max = sig["entropy_range"]
        if e_min <= entropy <= e_max:
            confidence += 30

        # Pulse ratio match
        r_min, r_max = sig["pulse_ratio"]
        if r_min <= pulse_ratio <= r_max + 1:
            confidence += 20

        # Tri-state check for PT2262
        if chip_name == "PT2262" and detect_tri_state_encoding(bit_string):
            confidence += 10

        if confidence > best_conf:
            best_conf  = confidence
            best_match = chip_name
            best_info  = sig

    return best_match, min(best_conf, 95), best_info


def calculate_vulnerability_score(chip_name: str, chip_info: dict, entropy: float) -> dict:
    """
    Calculate a vulnerability score and generate CVSS-style assessment.

    Returns:
        dict: Vulnerability assessment with score, severity, and details
    """
    is_vulnerable = chip_info.get("vulnerable", False)

    if is_vulnerable:
        # Fixed code systems — high severity
        base_score = 8.1
        severity   = "HIGH"
        vector     = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        impact     = "Attacker can unlock vehicle/gate/door without physical key"
        exploitability = "Trivial — $15 SDR + 5 min capture"
    elif entropy > 0.9:
        # Strong rolling code
        base_score = 4.2
        severity   = "MEDIUM"
        vector     = "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
        impact     = "Requires RollJam attack — victim interaction needed"
        exploitability = "Moderate — requires specialized equipment + proximity"
    else:
        base_score = 3.0
        severity   = "LOW"
        vector     = "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
        impact     = "Limited — cryptanalysis required"
        exploitability = "Difficult — requires cryptographic expertise"

    return {
        "cvss_score"    : base_score,
        "severity"      : severity,
        "cvss_vector"   : vector,
        "cwe_id"        : "CWE-294",
        "cwe_name"      : "Authentication Bypass by Capture-Replay",
        "impact"        : impact,
        "exploitability": exploitability,
        "attack_type"   : chip_info.get("attack", "Unknown"),
    }


def find_repeating_frame(bit_string: str) -> dict:
    """
    Find the fundamental repeating frame in a bit string.
    Key fobs typically repeat their code 3–12 times.
    """
    result = {"found": False, "frame": "", "repeat_count": 0, "frame_length": 0}

    for frame_len in range(8, len(bit_string) // 2 + 1):
        frame    = bit_string[:frame_len]
        repeated = 0
        pos      = 0
        while pos + frame_len <= len(bit_string):
            if bit_string[pos:pos+frame_len] == frame:
                repeated += 1
                pos += frame_len
            else:
                break
        if repeated >= 2:
            result["found"]        = True
            result["frame"]        = frame
            result["repeat_count"] = repeated
            result["frame_length"] = frame_len
            break

    return result


# ─────────────────────────────────────────────────
#  FULL ANALYSIS PIPELINE
# ─────────────────────────────────────────────────

def full_analysis(iq_path: str = None, simulate: bool = False,
                  signal_type: str = "fixed") -> dict:
    """
    Run complete signal analysis pipeline.

    Steps:
        1. Load or simulate IQ capture
        2. Demodulate and extract bits
        3. Pulse timing analysis
        4. Chip family identification
        5. Vulnerability assessment
        6. Generate full report

    Returns:
        dict: Complete analysis report
    """
    print("\n" + "="*60)
    print("  RF KEY FOB DEEP ANALYZER — wincr4ck Research")
    print("="*60 + "\n")

    # Load signal
    if simulate or iq_path is None:
        print(f"[*] Using simulated {signal_type} code signal")
        iq_samples = simulate_capture(signal_type=signal_type)
        source     = f"simulated_{signal_type}"
    else:
        print(f"[*] Loading: {iq_path}")
        iq_samples, _ = load_capture(iq_path)
        source         = iq_path

    # Demodulate
    amplitude  = normalize_amplitude(iq_to_amplitude(iq_samples))
    bits       = ook_demodulate(amplitude)
    pulses     = extract_pulses(bits, SAMPLE_RATE)
    bit_string = pulses_to_bits(pulses)
    p_start    = detect_preamble(bit_string)
    payload    = bit_string[p_start:]
    entropy    = calculate_entropy(payload)
    hex_data   = bits_to_hex(payload)

    # Advanced analysis
    timing        = analyze_pulse_timing(pulses)
    frame_info    = find_repeating_frame(payload)
    tri_state     = detect_tri_state_encoding(payload)
    manchester    = detect_manchester_encoding(payload)
    chip, conf, chip_info = match_chip_family(payload, pulses, entropy)
    vuln          = calculate_vulnerability_score(chip, chip_info, entropy)

    # Build report
    report = {
        "source"         : source,
        "frequency_mhz"  : 433.92,
        "signal": {
            "total_bits"   : len(bit_string),
            "payload_bits" : len(payload),
            "hex_payload"  : hex_data,
            "entropy"      : entropy,
            "tri_state"    : tri_state,
            "manchester"   : manchester,
        },
        "pulse_timing"   : timing,
        "frame_analysis" : frame_info,
        "chip_detection" : {
            "chip_family"  : chip,
            "confidence"   : conf,
            "description"  : chip_info.get("description", "Unknown chip"),
            "encoding"     : chip_info.get("encoding", "Unknown"),
        },
        "vulnerability"  : vuln,
        "remediation"    : get_remediation(chip_info),
    }

    print_analysis_report(report)
    return report


def get_remediation(chip_info: dict) -> list:
    """Return remediation recommendations based on chip type."""
    if chip_info.get("vulnerable", False):
        return [
            "Replace fixed-code system with AES-128 rolling code implementation",
            "Use KeeLoq+ or HCS512 with longer key space",
            "Implement time-based code expiration (codes valid <1 second)",
            "Add secondary challenge-response authentication",
            "Consider UWB (Ultra-Wideband) proximity verification (as in iPhone UWB car keys)",
            "Deploy RF anomaly detection to alert on replay attempts",
        ]
    else:
        return [
            "Minimize rolling code synchronization window (max 16 codes)",
            "Implement anti-RollJam: detect >2 consecutive missed codes",
            "Use bidirectional challenge-response (LF + UHF combined)",
            "Monitor for jamming signals on 433 MHz band",
            "Consider upgrade to ADAS-integrated keyless entry with UWB",
        ]


def print_analysis_report(report: dict):
    """Print formatted deep analysis report."""
    s  = report["signal"]
    cd = report["chip_detection"]
    v  = report["vulnerability"]
    f  = report["frame_analysis"]

    print("─"*60)
    print("  SIGNAL PROPERTIES")
    print("─"*60)
    print(f"  Frequency      : {report['frequency_mhz']} MHz")
    print(f"  Total Bits     : {s['total_bits']}")
    print(f"  Payload Bits   : {s['payload_bits']}")
    print(f"  Hex Payload    : {s['hex_payload'][:24]}...")
    print(f"  Shannon Entropy: {s['entropy']} (1.0 = fully random)")
    print(f"  Tri-state Enc  : {s['tri_state']}")
    print(f"  Manchester Enc : {s['manchester']}")

    print("\n─"*1 + "─"*59)
    print("  CHIP FAMILY DETECTION")
    print("─"*60)
    print(f"  Detected Chip  : {cd['chip_family']}")
    print(f"  Confidence     : {cd['confidence']}%")
    print(f"  Encoding       : {cd['encoding']}")
    print(f"  Description    :")
    for line in cd['description'].split('. '):
        if line:
            print(f"    {line}.")

    if f["found"]:
        print(f"\n  Frame Analysis : {f['frame_length']}-bit frame, repeated {f['repeat_count']}x")
        print(f"  Frame (hex)    : {bits_to_hex(f['frame'])}")

    print("\n─"*1 + "─"*59)
    print("  VULNERABILITY ASSESSMENT")
    print("─"*60)
    sev_icon = "🔴" if v["severity"] == "HIGH" else "🟡" if v["severity"] == "MEDIUM" else "🟢"
    print(f"  {sev_icon} CVSS Score    : {v['cvss_score']} ({v['severity']})")
    print(f"  CVSS Vector    : {v['cvss_vector']}")
    print(f"  CWE            : {v['cwe_id']} — {v['cwe_name']}")
    print(f"  Attack Type    : {v['attack_type']}")
    print(f"  Impact         : {v['impact']}")
    print(f"  Exploitability : {v['exploitability']}")

    print("\n─"*1 + "─"*59)
    print("  REMEDIATION")
    print("─"*60)
    for i, rem in enumerate(report["remediation"], 1):
        print(f"  [{i}] {rem}")

    print("─"*60 + "\n")


# ─────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="RF Key Fob Deep Analyzer — wincr4ck Security Research"
    )
    parser.add_argument('--iq',          type=str,  default=None,    help='Path to .iq capture file')
    parser.add_argument('--simulate',    action='store_true',        help='Use simulated signal')
    parser.add_argument('--signal-type', default='fixed',
                        choices=['fixed', 'rolling'],                help='Simulated signal type')
    parser.add_argument('--output',      type=str,  default=None,    help='Save JSON report to file')

    args = parser.parse_args()
    report = full_analysis(iq_path=args.iq, simulate=args.simulate,
                           signal_type=args.signal_type)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved: {args.output}")


if __name__ == "__main__":
    main()
