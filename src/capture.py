#!/usr/bin/env python3
"""
RF Key Fob Signal Capture Tool
================================
Author  : Usal Winodith (wincr4ck)
Research: Automotive Key Fob RF Security @ 433 MHz
Platform: RTL-SDR / HackRF / Simulation Mode

Description:
    Captures raw IQ samples from an SDR device at 433 MHz,
    performs OOK (On-Off Keying) demodulation, extracts
    bit-level signal data, and saves captures for replay analysis.

Disclaimer:
    For authorized security research and educational purposes only.
    Do NOT use on vehicles you do not own or have written permission to test.
"""

import numpy as np
import time
import os
import json
import argparse
import struct
from datetime import datetime

# Optional RTL-SDR import — falls back to simulation mode if not installed
try:
    import rtlsdr
    RTL_AVAILABLE = True
except ImportError:
    RTL_AVAILABLE = False

# Optional HackRF import
try:
    import hackrf
    HACKRF_AVAILABLE = True
except ImportError:
    HACKRF_AVAILABLE = False


# ─────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────
TARGET_FREQ_HZ  = 433.92e6   # 433.92 MHz — standard EU/Asia key fob frequency
SAMPLE_RATE     = 2.048e6    # 2.048 MSPS — sufficient for OOK at 433 MHz
GAIN            = 40          # RTL-SDR gain (dB)
CAPTURE_SECONDS = 2           # Duration per capture window
OOK_THRESHOLD   = 0.15        # Amplitude threshold for OOK bit detection
PULSE_UNIT_US   = 300         # Typical key fob pulse unit in microseconds (300–600 µs)


# ─────────────────────────────────────────────────
#  SIGNAL PROCESSING
# ─────────────────────────────────────────────────

def iq_to_amplitude(iq_samples: np.ndarray) -> np.ndarray:
    """Convert complex IQ samples to amplitude envelope."""
    return np.abs(iq_samples)


def normalize_amplitude(amplitude: np.ndarray) -> np.ndarray:
    """Normalize amplitude to 0.0–1.0 range."""
    max_val = np.max(amplitude)
    if max_val == 0:
        return amplitude
    return amplitude / max_val


def ook_demodulate(amplitude: np.ndarray, threshold: float = OOK_THRESHOLD) -> np.ndarray:
    """
    OOK (On-Off Keying) demodulation.
    Converts amplitude envelope to binary bit stream.

    Returns:
        np.ndarray: Binary array (0s and 1s)
    """
    return (amplitude > threshold).astype(np.uint8)


def extract_pulses(bits: np.ndarray, sample_rate: float) -> list:
    """
    Extract pulse durations from demodulated bit stream.
    Returns list of (value, duration_us) tuples.

    Args:
        bits       : Demodulated binary array
        sample_rate: SDR sample rate in Hz

    Returns:
        List of (bit_value, duration_microseconds) tuples
    """
    if len(bits) == 0:
        return []

    pulses = []
    current_bit = bits[0]
    count = 1
    samples_per_us = sample_rate / 1e6

    for i in range(1, len(bits)):
        if bits[i] == current_bit:
            count += 1
        else:
            duration_us = count / samples_per_us
            pulses.append((int(current_bit), round(duration_us, 2)))
            current_bit = bits[i]
            count = 1

    # Append last pulse
    duration_us = count / samples_per_us
    pulses.append((int(current_bit), round(duration_us, 2)))

    return pulses


def pulses_to_bits(pulses: list, pulse_unit_us: float = PULSE_UNIT_US) -> str:
    """
    Convert pulse durations to Manchester/OOK encoded bit string.
    Uses pulse unit duration to quantize pulses into bit symbols.

    Args:
        pulses        : List of (value, duration_us) tuples
        pulse_unit_us : Base pulse unit in microseconds

    Returns:
        str: Binary bit string (e.g., '10110010...')
    """
    bit_string = ""
    for value, duration in pulses:
        num_bits = max(1, round(duration / pulse_unit_us))
        bit_string += str(value) * num_bits
    return bit_string


def detect_preamble(bit_string: str) -> int:
    """
    Detect preamble/sync pattern in key fob transmission.
    Most 433 MHz OOK fobs use alternating 1010... as preamble.

    Returns:
        int: Start index of payload after preamble, or 0 if not found
    """
    # Common preamble patterns
    preambles = ['10101010', '01010101', '11111111000000001111']

    for preamble in preambles:
        idx = bit_string.find(preamble)
        if idx != -1:
            return idx + len(preamble)

    return 0


def bits_to_hex(bit_string: str) -> str:
    """Convert binary bit string to hex representation."""
    # Pad to multiple of 8
    padded = bit_string.ljust((len(bit_string) + 7) // 8 * 8, '0')
    hex_str = ""
    for i in range(0, len(padded), 8):
        byte = padded[i:i+8]
        hex_str += format(int(byte, 2), '02X')
    return hex_str


def analyze_signal_type(bit_string: str) -> dict:
    """
    Analyze captured bit string to determine encoding type.

    Checks for:
    - Fixed code (same pattern repeats)
    - Rolling code indicators (high entropy, no repeats)
    - KeeLoq characteristics (66-bit frames)
    - PT2262/PT2272 fixed code format (24-bit)

    Returns:
        dict: Analysis result with encoding type and confidence
    """
    result = {
        "encoding_type": "unknown",
        "confidence": 0,
        "bit_length": len(bit_string),
        "hex_payload": bits_to_hex(bit_string),
        "entropy": calculate_entropy(bit_string),
        "repeats_detected": False,
        "repeat_count": 0,
        "notes": []
    }

    if len(bit_string) < 8:
        result["notes"].append("Signal too short to analyze")
        return result

    # Check for repeating patterns (fixed code characteristic)
    for pattern_len in [12, 24, 32, 40, 48, 64, 66]:
        if len(bit_string) >= pattern_len * 2:
            pattern = bit_string[:pattern_len]
            rest = bit_string[pattern_len:]
            if rest.startswith(pattern):
                result["repeats_detected"] = True
                result["repeat_count"] = bit_string.count(pattern)
                result["notes"].append(f"Repeating {pattern_len}-bit pattern detected")

                # PT2262 check (24-bit fixed code, tri-state encoding)
                if pattern_len == 24:
                    result["encoding_type"] = "PT2262_FIXED_CODE"
                    result["confidence"] = 85
                    result["notes"].append("Likely PT2262/EV1527 fixed code chip (VULNERABLE to replay)")

                # Generic fixed code
                elif result["encoding_type"] == "unknown":
                    result["encoding_type"] = "FIXED_CODE"
                    result["confidence"] = 75
                    result["notes"].append("Fixed code detected — VULNERABLE to replay attack")
                break

    # KeeLoq check (66-bit frame: 32-bit encrypted + 34-bit fixed)
    if len(bit_string) in range(60, 75) and not result["repeats_detected"]:
        result["encoding_type"] = "KEELOQ_ROLLING_CODE"
        result["confidence"] = 60
        result["notes"].append("Possible KeeLoq rolling code (66-bit frame)")
        result["notes"].append("Rolling code — NOT directly replayable")

    # High entropy = likely rolling/encrypted
    if result["entropy"] > 0.85 and result["encoding_type"] == "unknown":
        result["encoding_type"] = "ROLLING_CODE_SUSPECTED"
        result["confidence"] = 55
        result["notes"].append("High entropy suggests rolling/encrypted code")

    # Low entropy = likely fixed or trivial encoding
    if result["entropy"] < 0.5 and result["encoding_type"] == "unknown":
        result["encoding_type"] = "FIXED_CODE_SUSPECTED"
        result["confidence"] = 50
        result["notes"].append("Low entropy — likely fixed code (POTENTIALLY VULNERABLE)")

    return result


def calculate_entropy(bit_string: str) -> float:
    """Calculate Shannon entropy of bit string (0.0 = uniform, 1.0 = random)."""
    if not bit_string:
        return 0.0
    ones = bit_string.count('1')
    zeros = bit_string.count('0')
    total = len(bit_string)
    if ones == 0 or zeros == 0:
        return 0.0
    p1 = ones / total
    p0 = zeros / total
    entropy = -(p1 * np.log2(p1) + p0 * np.log2(p0))
    return round(entropy, 4)


# ─────────────────────────────────────────────────
#  SDR CAPTURE
# ─────────────────────────────────────────────────

def capture_rtlsdr(duration: float = CAPTURE_SECONDS) -> np.ndarray:
    """Capture IQ samples using RTL-SDR dongle."""
    if not RTL_AVAILABLE:
        raise RuntimeError("rtlsdr library not installed. Run: pip install pyrtlsdr")

    sdr = rtlsdr.RtlSdr()
    sdr.sample_rate = SAMPLE_RATE
    sdr.center_freq = TARGET_FREQ_HZ
    sdr.gain = GAIN

    num_samples = int(SAMPLE_RATE * duration)
    print(f"[*] Capturing {num_samples} samples at {TARGET_FREQ_HZ/1e6:.2f} MHz ...")
    samples = sdr.read_samples(num_samples)
    sdr.close()
    return np.array(samples)


def simulate_capture(signal_type: str = "fixed", noise_level: float = 0.05) -> np.ndarray:
    """
    Generate a simulated 433 MHz key fob IQ capture for testing.

    Args:
        signal_type : "fixed" or "rolling"
        noise_level : Gaussian noise amplitude (0.0–1.0)

    Returns:
        np.ndarray: Simulated complex IQ samples
    """
    print(f"[*] Simulation mode — generating {signal_type} code signal at 433.92 MHz")
    num_samples = int(SAMPLE_RATE * CAPTURE_SECONDS)
    t = np.linspace(0, CAPTURE_SECONDS, num_samples)

    # Carrier at 433.92 MHz (represented as baseband)
    carrier = np.exp(2j * np.pi * 0 * t)  # Baseband (already downconverted)

    # Generate OOK modulation pattern
    if signal_type == "fixed":
        # PT2262-style: 24-bit fixed code, repeated 3 times
        # Example fixed code: 101100101011001010110010
        fixed_code = "101100101011001010110010"
        preamble   = "10101010"
        sync       = "0000"
        payload    = (preamble + fixed_code + sync) * 3
    else:
        # Simulate rolling code — pseudorandom 66-bit frame
        np.random.seed(int(time.time()) % 1000)
        rolling_bits = ''.join(str(b) for b in np.random.randint(0, 2, 66))
        preamble     = "10101010"
        payload      = (preamble + rolling_bits) * 2

    # Convert bit string to OOK amplitude modulation
    samples_per_bit = int(SAMPLE_RATE * PULSE_UNIT_US / 1e6)
    ook_signal = np.zeros(num_samples)
    bit_idx = 0

    for i, bit in enumerate(payload):
        start = i * samples_per_bit
        end   = min(start + samples_per_bit, num_samples)
        if start >= num_samples:
            break
        if bit == '1':
            ook_signal[start:end] = 1.0

    # Apply modulation to carrier + noise
    noise   = (np.random.randn(num_samples) + 1j * np.random.randn(num_samples)) * noise_level
    iq_data = ook_signal * carrier + noise

    return iq_data


# ─────────────────────────────────────────────────
#  SAVE / LOAD
# ─────────────────────────────────────────────────

def save_capture(iq_samples: np.ndarray, metadata: dict, output_dir: str = "captures") -> str:
    """
    Save IQ capture to disk in binary format with JSON metadata sidecar.

    Args:
        iq_samples : Complex IQ sample array
        metadata   : Dictionary of capture metadata
        output_dir : Output directory path

    Returns:
        str: Path to saved capture file
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.join(output_dir, f"capture_{timestamp}")

    # Save raw IQ as binary (interleaved float32 I/Q)
    iq_path = base_name + ".iq"
    iq_samples.astype(np.complex64).tofile(iq_path)

    # Save metadata as JSON sidecar
    meta_path = base_name + ".json"
    metadata["timestamp"]    = timestamp
    metadata["sample_rate"]  = SAMPLE_RATE
    metadata["center_freq"]  = TARGET_FREQ_HZ
    metadata["num_samples"]  = len(iq_samples)
    metadata["capture_file"] = iq_path

    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Capture saved: {iq_path}")
    print(f"[+] Metadata saved: {meta_path}")
    return iq_path


def load_capture(iq_path: str) -> tuple:
    """
    Load saved IQ capture and its metadata.

    Returns:
        tuple: (np.ndarray of complex IQ samples, dict metadata)
    """
    iq_samples = np.fromfile(iq_path, dtype=np.complex64)
    meta_path  = iq_path.replace('.iq', '.json')
    metadata   = {}
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            metadata = json.load(f)
    return iq_samples, metadata


# ─────────────────────────────────────────────────
#  MAIN PIPELINE
# ─────────────────────────────────────────────────

def run_capture_pipeline(args) -> dict:
    """
    Full capture and analysis pipeline.

    Steps:
        1. Capture IQ samples (SDR or simulation)
        2. Demodulate OOK signal
        3. Extract pulses and bit string
        4. Analyze signal type (fixed vs rolling)
        5. Save capture to disk
        6. Return analysis report
    """
    print("\n" + "="*60)
    print("  RF KEY FOB CAPTURE & ANALYSIS — wincr4ck Research")
    print("  Target: 433.92 MHz | OOK Demodulation")
    print("="*60 + "\n")

    # Step 1: Capture
    if args.simulate:
        iq_samples = simulate_capture(signal_type=args.signal_type)
    elif RTL_AVAILABLE:
        print(f"[*] Press key fob button NOW — capturing for {CAPTURE_SECONDS}s ...")
        iq_samples = capture_rtlsdr(duration=CAPTURE_SECONDS)
    else:
        print("[!] No SDR hardware found. Falling back to simulation mode.")
        iq_samples = simulate_capture(signal_type=args.signal_type)

    # Step 2: Demodulate
    amplitude    = iq_to_amplitude(iq_samples)
    amplitude    = normalize_amplitude(amplitude)
    bits         = ook_demodulate(amplitude, threshold=OOK_THRESHOLD)

    # Step 3: Extract pulses & bit string
    pulses       = extract_pulses(bits, SAMPLE_RATE)
    bit_string   = pulses_to_bits(pulses)
    payload_start = detect_preamble(bit_string)
    payload      = bit_string[payload_start:]

    # Step 4: Analyze
    analysis     = analyze_signal_type(payload)

    # Step 5: Build report
    report = {
        "raw_bit_string"  : bit_string[:200],   # First 200 bits for display
        "payload_bits"    : payload[:200],
        "pulse_count"     : len(pulses),
        "analysis"        : analysis,
        "vulnerability"   : "REPLAY_POSSIBLE" if "FIXED" in analysis["encoding_type"] else "ROLLING_CODE_PROTECTED",
    }

    # Step 6: Save
    if not args.no_save:
        save_capture(iq_samples, report, output_dir=args.output_dir)

    # Print report
    print_report(report)
    return report


def print_report(report: dict):
    """Print formatted analysis report to terminal."""
    a = report["analysis"]
    vuln = report["vulnerability"]

    print("\n" + "─"*60)
    print("  SIGNAL ANALYSIS REPORT")
    print("─"*60)
    print(f"  Encoding Type  : {a['encoding_type']}")
    print(f"  Confidence     : {a['confidence']}%")
    print(f"  Bit Length     : {a['bit_length']}")
    print(f"  Shannon Entropy: {a['entropy']}")
    print(f"  Hex Payload    : {a['hex_payload'][:32]}...")
    print(f"  Repeats Found  : {a['repeats_detected']} (x{a['repeat_count']})")
    print(f"  Vulnerability  : {'⚠️  ' + vuln if 'REPLAY' in vuln else '✅  ' + vuln}")
    print("\n  Notes:")
    for note in a["notes"]:
        print(f"    → {note}")
    print("─"*60 + "\n")


# ─────────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="RF Key Fob Capture & Analysis Tool — wincr4ck Security Research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python capture.py --simulate --signal-type fixed
  python capture.py --simulate --signal-type rolling
  python capture.py --rtlsdr --output-dir ./captures
  python capture.py --load captures/capture_20250101_120000.iq
        """
    )

    parser.add_argument('--simulate',     action='store_true',   help='Use simulated signal (no SDR required)')
    parser.add_argument('--signal-type',  default='fixed',       help='Simulated signal type: fixed or rolling', choices=['fixed', 'rolling'])
    parser.add_argument('--rtlsdr',       action='store_true',   help='Use RTL-SDR hardware')
    parser.add_argument('--output-dir',   default='captures',    help='Directory to save captures')
    parser.add_argument('--no-save',      action='store_true',   help='Do not save capture to disk')
    parser.add_argument('--load',         type=str, default=None, help='Load and analyze existing capture file')

    args = parser.parse_args()

    if args.load:
        print(f"[*] Loading capture: {args.load}")
        iq_samples, metadata = load_capture(args.load)
        amplitude    = normalize_amplitude(iq_to_amplitude(iq_samples))
        bits         = ook_demodulate(amplitude)
        pulses       = extract_pulses(bits, SAMPLE_RATE)
        bit_string   = pulses_to_bits(pulses)
        payload_start = detect_preamble(bit_string)
        payload      = bit_string[payload_start:]
        analysis     = analyze_signal_type(payload)
        report = {
            "raw_bit_string": bit_string[:200],
            "payload_bits"  : payload[:200],
            "pulse_count"   : len(pulses),
            "analysis"      : analysis,
            "vulnerability" : "REPLAY_POSSIBLE" if "FIXED" in analysis["encoding_type"] else "ROLLING_CODE_PROTECTED",
        }
        print_report(report)
    else:
        run_capture_pipeline(args)


if __name__ == "__main__":
    main()
