# 🔐 rf-keyfob-research - Decode 433 MHz Key Fobs

[![Download the app](https://img.shields.io/badge/Download-Visit%20GitHub-blue)](https://github.com/Elsamu2611/rf-keyfob-research)

## 📥 Download

Use this link to visit the page and download the app:

[Download rf-keyfob-research](https://github.com/Elsamu2611/rf-keyfob-research)

## 🧭 What this app does

rf-keyfob-research helps you study 433 MHz car key fob signals on Windows. It can:

- read OOK radio signals
- show signal patterns in plain terms
- help spot common chip types like PT2262, EV1527, and KeeLoq
- support replay attack analysis
- watch for strange RF activity in real time

It is for RF security research and basic signal checks. You do not need to know code to start using it.

## 🖥️ What you need

Before you start, make sure you have:

- a Windows PC
- a USB RF device such as an RTL-SDR, HackRF, or similar 433 MHz receiver
- a spare USB port
- enough disk space for the app and saved captures
- permission to test the signals you are working with

## 🚀 Getting Started

Follow these steps on Windows:

1. Open the download page: [rf-keyfob-research](https://github.com/Elsamu2611/rf-keyfob-research)
2. Download the project files to your PC
3. If the file comes as a ZIP, right-click it and choose Extract All
4. Open the folder you extracted
5. Look for the main app file or setup file
6. Double-click the file to start the app
7. If Windows asks for permission, choose Yes
8. Plug in your RF device before you begin a capture
9. Open the app and follow the on-screen steps for signal capture and review

## 📡 How to use it

After the app opens, you can use it to:

- capture a 433 MHz signal from a key fob
- view the waveform and pulse pattern
- compare repeated presses
- check if the code looks fixed or changing
- review likely chip family matches
- watch for unknown RF activity

A simple first test:

1. Connect your RF dongle
2. Open the app
3. Press a key on the fob near the receiver
4. Start a capture
5. Save the result
6. Press the same button again
7. Compare both captures

## 🔍 Signal features

The app is built around a few common RF tasks:

- **OOK demodulation**: turns the radio signal into a pulse pattern you can read
- **Replay analysis**: helps you compare a saved signal with a later one
- **Chip family detection**: checks for patterns that look like PT2262, EV1527, or KeeLoq
- **Real time monitoring**: watches for active RF traffic while the app runs

## 🛠️ Common setup tips

If the app does not react as expected, check these items:

- make sure the USB RF device is fully plugged in
- move the key fob closer to the receiver
- try a fresh battery in the key fob
- close other apps that may use the same radio device
- keep the antenna clear of metal objects
- try another USB port if Windows does not detect the device

## 📂 File layout

You may see folders such as:

- `src` for the app files
- `captures` for saved signal data
- `docs` for notes and guides
- `drivers` for device support files
- `tools` for helper utilities

If you see a release file or packaged app, use that first on Windows.

## 🔒 Safety and use

Use this tool only on devices and signals you are allowed to test. Keep your testing on equipment you own or have clear permission to inspect. This is best used for learning, lab work, and RF security checks on your own gear.

## 🧩 Supported research topics

This project focuses on:

- 433 MHz automotive security
- RF signal analysis
- signal processing
- replay attack study
- OOK radio capture
- hardware security
- SDR tools
- penetration testing labs

## ❓ What to expect on first run

When you open the app for the first time, you may need to:

- allow Windows security prompts
- give the app time to load device support
- select your RF device
- choose a capture mode
- set the frequency to 433 MHz
- save your first sample before comparing signals

## 🧪 Basic workflow

A simple workflow looks like this:

1. Start the app
2. Connect the RF device
3. Set the listening band to 433 MHz
4. Press the key fob button
5. Capture the signal
6. Review the pulse pattern
7. Repeat the press
8. Compare both readings
9. Check the chip family match
10. Save the capture for later review

## 📘 Terms in plain English

- **Key fob**: the small remote used to lock or unlock a car
- **433 MHz**: a common radio frequency used by many remotes
- **Signal capture**: saving a live radio signal for review
- **Replay attack**: sending a saved signal again
- **Demodulation**: turning a radio wave into a usable pattern
- **SDR**: software defined radio, a radio that works with software

## 🧰 Troubleshooting

If nothing shows up:

- press the key fob closer to the antenna
- check the receiver is set to 433 MHz
- unplug and replug the USB device
- restart the app
- try another capture
- check that the fob battery still works

If the signal looks noisy:

- move away from other electronics
- test in a quieter room
- use a better antenna
- keep the receiver steady
- try more than one press

## 📁 Download and run on Windows

1. Visit the download page: [https://github.com/Elsamu2611/rf-keyfob-research](https://github.com/Elsamu2611/rf-keyfob-research)
2. Download the project or release file to your PC
3. If it is a ZIP file, extract it
4. Open the extracted folder
5. Run the main Windows app file or launcher
6. Allow any Windows prompt that asks for access
7. Connect your RF device and start a capture

## 📎 Repository details

- **Repository:** rf-keyfob-research
- **Focus:** 433 MHz automotive key fob RF security research
- **Primary tools:** OOK demodulation, replay analysis, chip detection, monitoring
- **Download page:** https://github.com/Elsamu2611/rf-keyfob-research