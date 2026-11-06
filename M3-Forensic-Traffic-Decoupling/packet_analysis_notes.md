# Forensic Packet Decoupling & Protocol Dissection Notes
**Target Filter:** `tcp.port == 2222`  
**Capture Interface:** `eth0` (`10.0.0.3` Kali Auditing Node)  
**Target Node:** `10.0.0.5:2222` (Ubuntu Server Cowrie Listener)  
**Deliverable PCAP:** `traffic_capture.pcap`

---

## 1. TCP Three-Way Handshake Breakdown (Frames 10-12)

```text
Client (10.0.0.3:36866)                     Honeypot (10.0.0.5:2222)
       |                                              |
       |  Frame 10: [SYN]                             |
       |  Seq=0, Win=64240, MSS=1460, SACK Permitted  |
       |--------------------------------------------->|
       |                                              |
       |  Frame 11: [SYN, ACK]                        |
       |  Seq=0, Ack=1, Win=65160, MSS=1460           |
       |<---------------------------------------------|
       |                                              |
       |  Frame 12: [ACK]                             |
       |  Seq=1, Ack=1, Win=64256                     |
       |--------------------------------------------->|
       |                                              |
       |  === CONNECTION TRANSITIONS TO ESTABLISHED ===|
```

* **Frame 10 (Client -> Server) [SYN]:** Kali initializes stream. Window size 64240, MSS 1460.
* **Frame 11 (Server -> Client) [SYN, ACK]:** Cowrie listener acknowledges receipt, sets Window 65160.
* **Frame 12 (Client -> Server) [ACK]:** Client finalizes 3-way handshake (`Ack=1`, `Seq=1`).

---

## 2. SSH Protocol Version String Exchange (Frames 13-14)

Prior to cryptographic encapsulation, cleartext identification strings are transmitted:
* **Frame 13 (Server -> Client):** `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n`  
  * *Analysis:* Mimics Debian 12 Bookworm OpenSSH release.
* **Frame 14 (Client -> Client):** `SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n`  
  * *Analysis:* Authentic client signature from Kali Linux 2024/2026 rolling distribution.

---

## 3. Cryptographic Key Exchange Initialization (Frames 15-16: `SSH_MSG_KEXINIT`)

Both peers dispatch message type `20` (`SSH_MSG_KEXINIT`) specifying supported cryptographic suites:
* **Key Exchange Algorithms:** `curve25519-sha256`, `ecdh-sha2-nistp256`, `diffie-hellman-group14-sha256`
* **Host Key Algorithms:** `rsa-sha2-512`, `rsa-sha2-256`, `ssh-ed25519`
* **Symmetric Encryption (Client-to-Server / Server-to-Client):** `chacha20-poly1305@openssh.com`, `aes128-ctr`, `aes256-gcm@openssh.com`
* **Data Integrity / MAC:** `hmac-sha2-256`, `hmac-sha2-512`
* **Compression:** `none`
