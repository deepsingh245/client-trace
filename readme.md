# Client‑Trace Front‑End Test Suite & Demo

## 📖 Overview
This branch of **client‑trace** contains only the front‑end assets (HTML, CSS, and JavaScript) that demonstrate the security‑focused `client‑trace` library. It provides a **premium dark‑mode UI** with smooth micro‑animations, allowing you to manually trigger each of the 14 security modules and view real‑time results.

---

## ✨ Features
- **Interactive UI** – Buttons, input fields and live result panels.
- **Full‑screen dark theme** with glass‑morphism style and subtle animations.
- **Real‑time monitoring** – Bot‑behaviour detection, network‑timing analysis, CSP listening, etc.
- **Transport security** – HMAC signing, AES‑GCM encryption, nonce generation.
- **Comprehensive report** – One‑click generation of a JSON security report covering all modules.
- **Extensible** – Add new tests by editing `app.js`.

---

## 🛠 Prerequisites
- **Node.js** (v18 or newer).
- A modern browser that supports ES‑modules and the Web Crypto API.

---

## 🚀 Getting Started

### 1. Installation
Install the dependencies:
```bash
npm install
```

### 2. Development
Start the local development server with hot reload:
```bash
npm run dev
```
The app will open automatically at `http://localhost:3000`.

### 3. Production Build
To create an optimized production build:
```bash
npm run build
```
The output will be in the `dist/` folder, ready to be deployed to any static hosting service (Vercel, Netlify, GitHub Pages, etc.).

You can preview the production build locally:
```bash
npm run preview
```

> **Note:** Opening `index.html` directly from the file system will not work because ES‑modules require an HTTP server.

---

## 📚 How to Use the UI
| Section | What it does | How to try it |
|---------|--------------|--------------|
| **Integrity Verification** | Checks bundle hash and validates a signed session token. | Click *Generate Token*, then *Verify Token*.
| **Network Analysis** | Detects fetch‑tampering, proxy signatures and timing anomalies. | Use *Simulate Tampering* → *Detect Tampering*.
| **Fingerprint & Bot Detection** | Generates a device fingerprint and analyses mouse‑movement entropy. | Click *Start Monitoring*, move the mouse, then *Detect Bot*.
| **Security Monitoring** | CSP listener, script‑injection detection, storage tampering. | Use *Start CSP Listener* and *Inject Test Script*.
| **Transport Security** | HMAC signing, AES‑GCM encryption, nonce generation. | Fill the JSON payload fields and press the corresponding *Sign* / *Encrypt* buttons.
| **Full Report** | Runs every check and outputs a consolidated JSON report. | Click *Generate Full Report*.

All results appear in the collapsible **Result** panel below each test card, colour‑coded (green = success, red = error, orange = warning).

---

## 🐞 Troubleshooting
- **Modules won’t load** – Ensure you are serving the files via HTTP. Opening `index.html` directly will fail.
- **Bot detection always low** – Move the mouse around for a few seconds before clicking *Detect Bot*; the algorithm needs enough entropy.
- **Signature verification fails** – Verify that the backend signing endpoint (`http://localhost:3000/api/...`) is reachable if you are using the default server.
- **Encryption errors** – The secret must be at least 16 characters; AES‑GCM requires a 96‑bit nonce.

---

## 📦 Project Structure
```
client-trace/
├─ dist/               # Production build output
├─ index.html          # Main UI entry point
├─ style.css           # Premium dark‑mode stylesheet
├─ app.js              # Front‑end logic (event handlers, UI updates)
├─ package.json        # Project configuration & scripts
├─ vite.config.js      # Vite configuration
└─ README.md           # Documentation
```

---

## 📄 License
ISC – see the LICENSE file for details.

---

*Happy testing!* 🎉
