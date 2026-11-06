================================================================================
ASSIGNMENT 1 FORENSIC EVIDENCE & MASTER DELIVERABLES INDEX
Report ID: IR-2026-1031-01
Author: Qazeem Samsudeen Temitope (BlaqqSec)
Engagement Date: November 2026
Auditing Node: Kali Linux (10.0.0.3)
Target Node: Ubuntu Server 22.04 LTS (10.0.0.5)
================================================================================

1. PRIMARY DELIVERABLES & CLOUD REPOSITORIES
--------------------------------------------------------------------------------
All raw artifacts, PCAP dumps, terminal captures, and telemetry logs have been 
curated and verified inside the centralized Google Drive evidence repository:

[Public Google Drive Folder]
URL: https://drive.google.com/drive/folders/11pmg1r_L5p1b5kA7-siHUgYEu2lDwriG

2. DIRECT ARTIFACT ACCESS MATRIX
--------------------------------------------------------------------------------
Artifact: Network Traffic Capture (traffic_capture.pcap)
Path: M3-Forensic-Traffic-Decoupling/traffic_capture.pcap
Storage Link: https://drive.google.com/drive/folders/11pmg1r_L5p1b5kA7-siHUgYEu2lDwriG
Description: Wireshark packet capture decoupling TCP 3-way handshake (Frames 10-12),
             SSH banner exchanges (Frames 13-14), and KEXINIT negotiation.

Artifact: Raw Nmap Reconnaissance Output (02_nmap_recon_scan_output.txt)
Path: M2-Reconnaissance-Auditing/02_nmap_recon_scan_output.txt
Storage Link: https://docs.google.com/document/d/1dflS0K64RLUT9f7RNOi-c5N8HI5-VzTXrcA_FkLpkDk/edit
Description: Full verbatim terminal output for 'nmap -sV -p 2222 10.0.0.5' 
             including public host keys and VirtualBox OUI.

Artifact: Honeypot Session Telemetry (03_cowrie_session_telemetry.json)
Path: M4-Telemetry-Adversary-Analysis/03_cowrie_session_telemetry.json
Storage Link: https://docs.google.com/document/d/1cFHRexTXxjVHQ1oaAGs2RWsYnpaIkKi7yFMhVhyD7QI/edit
Description: Asynchronous machine-readable JSON telemetry recording intrusion
             session 7854fe4b6204, credential testing, commands, and timing.

Artifact: Master Index & Checksums (README_EVIDENCE_INDEX.txt)
Path: Deliverables/README_EVIDENCE_INDEX.txt
Storage Link: https://docs.google.com/document/d/17F7qNAz4-Td5byF3WKUzWRhLX8G3oVRDuXmOhi4eiFY/edit
Description: Master verification index and cryptographic record.

3. FORENSIC VERIFICATION & AUDIT INTEGRITY
--------------------------------------------------------------------------------
Integrity verification confirmed against standard SHA256 checksums:
Session ID: 7854fe4b6204
TTY Log SHA256: aaaa3c835cde5b9e72f726bfc62eacf39ff08b7e801464b6c1cc22241a1a314f
Report ID: IR-2026-1031-01
================================================================================
