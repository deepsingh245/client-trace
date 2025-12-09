# Client-Trace Test Suite

This directory contains an interactive test suite and demo application for the `client-trace` library.

## Overview

The test suite provides a visual interface to test all 14 security modules in the library. It includes interactive buttons, input fields, and real-time result displays.

## Features

✅ **Interactive UI** - Premium dark-mode interface with smooth animations  
✅ **Live Testing** - Test each module individually or run a full security report  
✅ **Visual Feedback** - Color-coded results (success, warning, error)  
✅ **Real-time Monitoring** - Test behavioral detection with live mouse tracking  
✅ **Attack Simulation** - Simulate tampering and injection attacks to verify detection

## How to Run

### Prerequisite
You need **Node.js** installed on your machine.

### Start the Test Environment
1.  Open a terminal in the repository root.
2.  Run the dedicated test server:
    ```bash
    node test/server.js
    ```
3.  Open your browser and navigate to:
    [http://localhost:3000/test/index.html](http://localhost:3000/test/index.html)

**Why a custom server?**  
The library uses modern browser APIs (`crypto.subtle`, `fetch`) and ES6 modules. A backend is also required to verify signatures, tokens, and encryption in a realistic way. The included `test/server.js` handles both static file serving and these API verifications.


## Test Guide

### 1. Integrity Verification
- **Bundle Integrity**: Tests SHA-256 hash verification of JavaScript files
- **Session Token**: Generates HMAC-signed tokens with user context

### 2. Network Analysis
- **Monkey-Patch Detection**: 
  1. Click "Simulate Tampering" to modify `fetch`
  2. Click "Detect Tampering" to verify detection
- **Proxy Detection**: Checks HTTP headers for proxy signatures
- **Timing Anomalies**: Measures network timing to detect MITM delays

### 3. Fingerprinting & Behavior
- **Device Fingerprint**: Generates a privacy-safe device identifier
- **Bot Detection**:
  1. Click "Start Monitoring"
  2. Move your mouse and click around naturally
  3. Click "Detect Bot" to see behavior analysis

### 4. Security Monitoring
- **Script Injection**:
  1. Click "Inject Test Script" to add a script tag
  2. Click "Detect Injections" to verify detection
- **CSP Listener**: Click "Start CSP Listener" to monitor policy violations
- **Storage Tampering**:
  1. Click "Initialize Storage" to set up monitoring
  2. Click "Tamper Storage" to modify a value
  3. Click "Check Integrity" to detect the change

### 5. Transport Security
- **Payload Signing**: Enter JSON data and a secret to generate HMAC signature
- **Encryption**: Enter JSON data and a secret to encrypt with AES-GCM
- **Nonce**: Generate and retrieve the current replay-protection nonce

### 6. Full Security Report
Click "Generate Full Report" to run all available security checks and get a comprehensive JSON report.

## Notes

- The test suite uses the library from `../src/index.js`
- Some tests (like bundle integrity) will show warnings by design
- Storage tampering tests use `localStorage` - check browser console for details
- Bot detection requires actual user interaction to work properly

## Troubleshooting

**Problem**: Cannot load ES6 modules  
**Solution**: Make sure you're serving via HTTP (use a local server)

**Problem**: `collectSecurityReport` returns partial data  
**Solution**: Some checks require configuration (e.g., `bundleUrl`, `expectedBundleHash`)

**Problem**: Bot detection always shows low entropy  
**Solution**: Move your mouse more and interact with the page before testing

## Browser Compatibility

Requires a modern browser with support for:
- ES6 Modules
- Web Crypto API (`crypto.subtle`)
- Performance API
- MutationObserver

Tested on:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## License

ISC
