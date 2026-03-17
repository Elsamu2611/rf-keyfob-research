#!/usr/bin/env python3
"""
RF Replay Attack Defense & Detection Module
=============================================
Author  : Usal Winodith (wincr4ck)
Research: Automotive Key Fob RF Security @ 433 MHz

Description:
    Defensive counterpart to the replay attack toolkit.
    Monitors 433 MHz spectrum for:
    - Replay attack signatures (identical repeated transmissions)
    - RF jamming indicators
    - Suspicious transmission patterns
    - Fixed-code transmissions (known vulnerable devices)

    Generates alerts and logs for forensic analysis.

Usage in Real World:
    - Security researchers monitoring lab environments
    - Automotive security engineers testing PEPS systems
    - Facility security testing garage/gate remotes
"""

import numpy as np
import time
import json
import os
import hashlib
import argparse
from datetime import datetime
from collections import deque, defaultdict

try:
    import rtlsdr
    RTL_AVAILABLE = True
except ImportError:
    RTL_AVAILABLE = False

from capture import (
    iq_to_amplitude, normalize_amplitude, ook_demodulate,
    extract_pulses, pulses_to_bits, detect_preamble,
    bits_to_hex, calculate_entropy, simulate_capture,
    SAMPLE_RATE, OOK_THRESHOLD
)


# ─────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────
TARGET_FREQ_HZ    = 433.92e6
MONITOR_WINDOW_S  = 0.5          # Monitoring window per scan
REPLAY_THRESHOLD  = 2            # Min identical captures to flag as replay
ENTROPY_JAM_MAX   = 0.15         # Below this = potential jamming (constant carrier)
SIGNAL_DB_SIZE    = 500          # Max signals stored in memory
ALERT_LOG         = "alerts.log"


# ─────────────────────────────────────────────────
#  SIGNAL FINGERPRINTING
# ─────────────────────────────────────────────────

def fingerprint_signal(bit_string: str) -> str:
    """
    Generate a unique fingerprint (SHA-256) of a signal's bit payload.
    Used to detect identical replayed signals.

    Args:
        bit_string : Decoded bit string of captured signal

    Returns:
        str: Hex SHA-256 fingerprint
    """
    return hashlib.sha256(bit_string.encode()).hexdigest()[:16]


def extract_signal_features(bit_string: str, pulses: list) -> dict:
    """
    Extract discriminating features for signal classification.

    Features used for replay detection:
    - Bit string hash (exact match)
    - Entropy (randomness)
    - Pulse count and timing
    - Bit length
    - Hex payload

    Returns:
        dict: Feature dictionary
    """
    return {
        "fingerprint"   : fingerprint_signal(bit_string),
        "bit_length"    : len(bit_string),
        "entropy"       : calculate_entropy(bit_string),
        "pulse_count"   : len(pulses),
        "hex_payload"   : bits_to_hex(bit_string)[:16],
        "timestamp"     : datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────
#  DETECTION ENGINES
# ─────────────────────────────────────────────────

class ReplayDetector:
    """
    Sliding-window replay attack detector.

    Maintains a history of recent signal fingerprints.
    Alerts when the same fingerprint appears more than
    REPLAY_THRESHOLD times within the time window.
    """

    def __init__(self, window_size: int = SIGNAL_DB_SIZE,
                 threshold: int = REPLAY_THRESHOLD,
                 time_window_s: float = 30.0):
        self.history       = deque(maxlen=window_size)
        self.fingerprints  = defaultdict(list)  # fingerprint → list of timestamps
        self.threshold     = threshold
        self.time_window   = time_window_s
        self.alert_count   = 0

    def check(self, features: dict) -> dict:
        """
        Check if a new signal is a replay of a previously seen signal.

        Returns:
            dict: Detection result with is_replay flag and details
        """
        fp        = features["fingerprint"]
        now       = time.time()

        # Clean old entries outside time window
        self.fingerprints[fp] = [t for t in self.fingerprints[fp]
                                  if now - t < self.time_window]

        # Record this observation
        self.fingerprints[fp].append(now)
        self.history.append(features)

        count     = len(self.fingerprints[fp])
        is_replay = count >= self.threshold

        result = {
            "is_replay"      : is_replay,
            "fingerprint"    : fp,
            "seen_count"     : count,
            "time_window_s"  : self.time_window,
            "alert_level"    : "HIGH" if is_replay else "NONE",
        }

        if is_replay:
            self.alert_count += 1
            result["message"] = (
                f"REPLAY ATTACK DETECTED! Signal fingerprint '{fp}' "
                f"seen {count}x in {self.time_window}s window."
            )

        return result


class JammingDetector:
    """
    RF jamming detector based on signal entropy analysis.

    A constant carrier (jammer) produces very low entropy signal.
    A normal RF environment has moderate entropy.
    A rolling code has high entropy.
    """

    def __init__(self, entropy_threshold: float = ENTROPY_JAM_MAX,
                 history_size: int = 20):
        self.threshold   = entropy_threshold
        self.history     = deque(maxlen=history_size)
        self.alert_count = 0

    def check(self, amplitude: np.ndarray) -> dict:
        """
        Check amplitude envelope for jamming indicators.

        Returns:
            dict: Jamming detection result
        """
        # Calculate signal statistics
        mean_amp    = float(np.mean(amplitude))
        std_amp     = float(np.std(amplitude))
        max_amp     = float(np.max(amplitude))

        # Convert to binary for entropy
        bits        = ook_demodulate(amplitude)
        bit_string  = ''.join(map(str, bits[:1000]))  # First 1000 bits
        entropy     = calculate_entropy(bit_string)

        # Jamming: constant HIGH signal = low entropy + high mean amplitude
        is_jamming  = (entropy < self.threshold and mean_amp > 0.5)

        self.history.append({
            "entropy"   : entropy,
            "mean_amp"  : mean_amp,
            "timestamp" : time.time()
        })

        result = {
            "is_jamming"  : is_jamming,
            "entropy"     : entropy,
            "mean_amp"    : round(mean_amp, 4),
            "std_amp"     : round(std_amp, 4),
            "alert_level" : "HIGH" if is_jamming else "NONE",
        }

        if is_jamming:
            self.alert_count += 1
            result["message"] = (
                f"RF JAMMING DETECTED! Constant carrier on 433.92 MHz. "
                f"Entropy: {entropy:.3f} (threshold: {self.threshold}). "
                f"This may indicate a RollJam attack in progress."
            )

        return result


class FixedCodeDetector:
    """
    Detects transmissions from known-vulnerable fixed-code devices.
    Alerts when a fixed-code (replayable) system is detected nearby.
    """

    def __init__(self):
        self.alert_count = 0

    def check(self, bit_string: str, entropy: float) -> dict:
        """
        Detect if the signal is from a fixed-code (vulnerable) device.

        Returns:
            dict: Detection result
        """
        is_fixed   = entropy < 0.75
        bit_len    = len(bit_string)

        # Check for PT2262/EV1527 characteristics
        is_pt2262  = (20 <= bit_len <= 28) and is_fixed
        is_ev1527  = (22 <= bit_len <= 26) and is_fixed

        chip_guess = "PT2262/EV1527" if (is_pt2262 or is_ev1527) else \
                     "Unknown Fixed Code" if is_fixed else "Rolling Code (Safe)"

        result = {
            "is_fixed_code" : is_fixed,
            "chip_guess"    : chip_guess,
            "bit_length"    : bit_len,
            "entropy"       : entropy,
            "alert_level"   : "MEDIUM" if is_fixed else "NONE",
        }

        if is_fixed:
            self.alert_count += 1
            result["message"] = (
                f"VULNERABLE FIXED-CODE DEVICE DETECTED! "
                f"Chip: {chip_guess}, Bits: {bit_len}, Entropy: {entropy:.3f}. "
                f"This device is susceptible to RF replay attacks."
            )

        return result


# ─────────────────────────────────────────────────
#  ALERT SYSTEM
# ─────────────────────────────────────────────────

class AlertManager:
    """Manages security alerts — logs to file and prints to console."""

    ICONS = {
        "HIGH"   : "🔴 [CRITICAL]",
        "MEDIUM" : "🟡 [WARNING] ",
        "LOW"    : "🔵 [INFO]    ",
        "NONE"   : "⬜ [OK]      ",
    }

    def __init__(self, log_file: str = ALERT_LOG):
        self.log_file    = log_file
        self.alert_count = 0

    def alert(self, level: str, message: str, details: dict = None):
        """Issue a security alert."""
        self.alert_count += 1
        timestamp = datetime.now().isoformat()
        icon      = self.ICONS.get(level, "❓")

        # Console output
        print(f"\n{icon} {timestamp}")
        print(f"         {message}")
        if details:
            for k, v in details.items():
                if k != "message":
                    print(f"         {k}: {v}")

        # Log to file — convert all values to JSON-serializable types
        def make_serializable(obj):
            if isinstance(obj, dict):
                return {k: make_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, (bool, int, float, str)) or obj is None:
                return obj
            else:
                return str(obj)

        log_entry = {
            "id"        : self.alert_count,
            "timestamp" : timestamp,
            "level"     : level,
            "message"   : message,
            "details"   : make_serializable(details or {})
        }
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")


# ─────────────────────────────────────────────────
#  MONITORING ENGINE
# ─────────────────────────────────────────────────

class RFMonitor:
    """
    Real-time 433 MHz RF monitor.
    Integrates all detection engines into a unified monitoring loop.
    """

    def __init__(self, simulate: bool = False):
        self.simulate        = simulate
        self.replay_det      = ReplayDetector()
        self.jamming_det     = JammingDetector()
        self.fixed_code_det  = FixedCodeDetector()
        self.alerts          = AlertManager()
        self.scan_count      = 0
        self.running         = False

    def scan_once(self, signal_type: str = "fixed") -> dict:
        """
        Perform a single scan window and run all detectors.

        Returns:
            dict: Scan results from all detectors
        """
        self.scan_count += 1

        # Capture or simulate
        if self.simulate:
            iq_samples = simulate_capture(signal_type=signal_type, noise_level=0.03)
        elif RTL_AVAILABLE:
            import rtlsdr
            sdr = rtlsdr.RtlSdr()
            sdr.sample_rate = SAMPLE_RATE
            sdr.center_freq = TARGET_FREQ_HZ
            sdr.gain        = 40
            num_samples     = int(SAMPLE_RATE * MONITOR_WINDOW_S)
            iq_samples      = np.array(sdr.read_samples(num_samples))
            sdr.close()
        else:
            iq_samples = simulate_capture(signal_type=signal_type)

        # Process signal
        amplitude  = normalize_amplitude(iq_to_amplitude(iq_samples))
        bits       = ook_demodulate(amplitude)
        pulses     = extract_pulses(bits, SAMPLE_RATE)
        bit_string = pulses_to_bits(pulses)
        p_start    = detect_preamble(bit_string)
        payload    = bit_string[p_start:] if p_start > 0 else bit_string
        entropy    = calculate_entropy(payload)

        # Run detectors
        features   = extract_signal_features(payload, pulses)
        replay_r   = self.replay_det.check(features)
        jamming_r  = self.jamming_det.check(amplitude)
        fixed_r    = self.fixed_code_det.check(payload, entropy)

        # Issue alerts
        if replay_r["is_replay"]:
            self.alerts.alert("HIGH", replay_r["message"], replay_r)

        if jamming_r["is_jamming"]:
            self.alerts.alert("HIGH", jamming_r["message"], jamming_r)

        if fixed_r["is_fixed_code"]:
            self.alerts.alert("MEDIUM", fixed_r["message"], fixed_r)

        return {
            "scan_number" : self.scan_count,
            "timestamp"   : datetime.now().isoformat(),
            "replay"      : replay_r,
            "jamming"     : jamming_r,
            "fixed_code"  : fixed_r,
        }

    def monitor(self, duration_s: float = 60.0, signal_type: str = "fixed"):
        """
        Run continuous monitoring for a specified duration.

        Args:
            duration_s  : Total monitoring duration in seconds
            signal_type : Simulated signal type (simulate mode only)
        """
        self.running = True
        start_time   = time.time()

        print("\n" + "="*60)
        print("  RF SECURITY MONITOR — wincr4ck Research")
        print(f"  Frequency : 433.92 MHz")
        print(f"  Duration  : {duration_s}s")
        print(f"  Mode      : {'Simulation' if self.simulate else 'Live RTL-SDR'}")
        print(f"  Alert Log : {ALERT_LOG}")
        print("="*60)
        print(f"\n[*] Monitoring started at {datetime.now().isoformat()}")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            while self.running and (time.time() - start_time) < duration_s:
                result = self.scan_once(signal_type=signal_type)

                # Status line
                elapsed = time.time() - start_time
                print(f"\r[{elapsed:5.1f}s] Scan #{result['scan_number']:04d} | "
                      f"Replay: {'⚠' if result['replay']['is_replay'] else '✓'} | "
                      f"Jamming: {'⚠' if result['jamming']['is_jamming'] else '✓'} | "
                      f"Fixed: {'⚠' if result['fixed_code']['is_fixed_code'] else '✓'} | "
                      f"Alerts: {self.alerts.alert_count}", end='', flush=True)

                time.sleep(0.1)

        except KeyboardInterrupt:
            print("\n\n[*] Monitoring stopped by user")

        self.print_summary()

    def print_summary(self):
        """Print monitoring session summary."""
        print("\n" + "─"*60)
        print("  MONITORING SESSION SUMMARY")
        print("─"*60)
        print(f"  Total Scans        : {self.scan_count}")
        print(f"  Total Alerts       : {self.alerts.alert_count}")
        print(f"  Replay Alerts      : {self.replay_det.alert_count}")
        print(f"  Jamming Alerts     : {self.jamming_det.alert_count}")
        print(f"  Fixed Code Alerts  : {self.fixed_code_det.alert_count}")
        print(f"  Alert Log          : {ALERT_LOG}")
        print("─"*60)


# ─────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="RF Key Fob Security Monitor — wincr4ck Research"
    )
    parser.add_argument('--simulate',    action='store_true',  help='Simulate signals (no SDR needed)')
    parser.add_argument('--signal-type', default='fixed',
                        choices=['fixed', 'rolling'],          help='Signal type for simulation')
    parser.add_argument('--duration',    type=float, default=30.0, help='Monitor duration in seconds')
    parser.add_argument('--once',        action='store_true',  help='Single scan only')

    args    = parser.parse_args()
    monitor = RFMonitor(simulate=args.simulate or not RTL_AVAILABLE)

    if args.once:
        result = monitor.scan_once(signal_type=args.signal_type)
        def make_serializable(obj):
            if isinstance(obj, dict):
                return {k: make_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [make_serializable(i) for i in obj]
            elif isinstance(obj, (bool, int, float, str)) or obj is None:
                return obj
            else:
                return str(obj)
        print(json.dumps(make_serializable(result), indent=2))
    else:
        monitor.monitor(duration_s=args.duration, signal_type=args.signal_type)


if __name__ == "__main__":
    main()
