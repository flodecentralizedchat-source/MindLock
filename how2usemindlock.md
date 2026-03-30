# How to Use MindLock 🔒
**Autonomous Data Security System — Files that Think and Defend Themselves**

This guide provides step-by-step instructions for using the MindLock CLI, from basic encryption to advanced self-defending policies.

---

## 🚀 Quick Start: The Basic Lock/Unlock
The most common use case is simply protecting a file with a password.

1. **Lock a file**:
   ```bash
   ./target/release/mindlock lock demo.txt --label "Personal Documents"
   ```
2. **Unlock it**:
   ```bash
   ./target/release/mindlock unlock demo.txt.mindlock -o restored.txt
   ```

---

## 🛡️ Advanced Security Policies
MindLock's power comes from its **Active Defense** policies. You can set these during the `lock` command.

### 1. The "Self-Destruct" (Dead Man's Switch)
Set a maximum number of failed unlock attempts. When the threshold is crossed, MindLock performs a **DoD 5220.22-M 3-pass wipe** on the data.
```bash
# Lock with a 3-strike self-destruct policy
./target/release/mindlock lock secret.txt --max-fails 3
```

### 2. Device Locking
Ensure a file **can only be opened on your computer**, even if someone has the password and the file.
```bash
./target/release/mindlock lock secret.txt --device-lock
```

### 3. Expiry & Open Limits
Set a file to "expire" after a certain date or a certain number of successful opens.
```bash
# File expires on Dec 31st and can only be opened 5 times
./target/release/mindlock lock report.pdf \
  --expires 2025-12-31 \
  --max-opens 5
```

---

## 🎭 Decoy Mode (Deception Defense)
If an attacker triggers a failed attempt, serve them a **fake file** instead of an error. This uses per-recipient watermarking to track who leaked the decoy.

1. **Lock with Decoy**:
   ```bash
   ./target/release/mindlock lock leak.csv --decoy
   ```
2. **Attacker Experience**: If they fail the security check, they see the `◈` (Decoy Active) marker and get a "decoy" version of the file that looks real but contains fake data.

---

## 🧠 Behavioral Biometrics (Phase 3)
Teach MindLock your "typing rhythm" to add a biometric layer without needing a camera or fingerprint reader.

1. **Enroll your behavior**:
   ```bash
   ./target/release/mindlock enroll your_file.mindlock
   ```
2. **What happens?** You type your password 5 times. MindLock learns the millisecond-level intervals between keys. Now, an attacker with your password will be denied because they don't *type* like you.

---

## 🌐 Phase 3 & 4: Remote Control & Web3
To manage your files remotely or use Token Gating, you need the **MindLock Daemon**.

1. **Start the services**:
   ```bash
   docker-compose up -d --build
   ```
2. **Register a file for Remote Revoke**:
   - Files with a `control_server` set will check the central daemon before opening.
   - You can log into the **Dashboard (Port 3000)** and click "Revoke" to instantly kill a file halfway across the world.

3. **Token Gating (Phase 4)**:
   Restrict access to users who hold a specific Ethereum/Polygon token.
   ```bash
   ./target/release/mindlock lock secret.txt \
     --token-contract 0x... \
     --min-balance 100
   ```

---

## 🔍 Management Commands

| Command | Usage | Description |
| :--- | :--- | :--- |
| `inspect` | `mindlock inspect file.mindlock` | Show metadata & policy without needing a password. |
| `status` | `mindlock status file.mindlock` | Show real-time access stats (fails, opens, wipe status). |
| `rekey` | `mindlock rekey file.mindlock` | Change the encryption password securely. |
| `wipe` | `mindlock wipe file.mindlock` | Manually trigger a 3-pass secure overwrite. |
| `add-device` | `mindlock add-device file.mindlock` | Trust a second computer to open a device-locked file. |

---

> [!CAUTION]
> **Warning**: Self-destruct and secure-wipe are **permanent**. Once a file is wiped, it is physically impossible to recover the data, even with forensic tools. Use these features only for truly sensitive data!
