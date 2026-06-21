# Xiaomi Private Album Decryptor

A Python utility for recovering photos and videos from Xiaomi/POCO Gallery private album backups (.lsa and .lsav).

## Why I Built This

 lost my access to  my privacy passw on an xiaomi device so made an AI-assisted Python utility for recovering Xiaomi/POCO Gallery private album backups (.lsa/.lsav). Built after recovering 679 encrypted files from a locked private album, with support for large files, resume, reporting, and low-memory processing where low specs pc could easily handle large files

## Features

- AES-CTR decryption
- Recursive folder scanning
- Resume support
- CSV and JSON reports
- Low-memory processing
- HDD/SSD-aware tuning
- Collision-safe output naming
- Single-file and folder support
- Graceful interruption handling

## Real-world Test

- Files recovered: 679
- Success rate: 100%
- Backup size: ~26 GB
- Recovery time: ~190 seconds

## Requirements

pip install -r requirements.txt

## Disclaimer

Use only on backups and files you own or are authorized to recover.


step by step process

step 1

Download the Repository
Download the project from GitHub:
Code → Download ZIP
get the zip file from the device contaning .lsa/.lsav files
generally present at
internal storage> miui > gallery > backup 
if not 
just search .lsa in search of internal storage and get the location

step 2 


get the zip file in computer <img width="685" height="292" alt="screenshot" src="https://github.com/user-attachments/assets/1c48d39a-3114-4a32-a47c-377c56666c3e" />
 unzip file
 it may show error if the fie size is big if it does
 try opening it with 7 zip application
download the python file xiaomi_decrypt_adi_v1.0.0_github.

step 3
before in cmd 
Install Required Libraries
Open Command Prompt inside the project folder.
Run:
pip install -r requirements.txt
Expected output:
Successfully installed pycryptodome filetype psutil

step 4

Run The Script
Open Command Prompt in the project folder.
Run:
python xiaomi_decrypt_adi_v1.0.0_github.py "C:\Backup\secretAlbum"
Replace the path with your own backup location.

 step 5
 Wait For Processing

The script will automatically:
✅ Scan folders
✅ Detect .lsa and .lsav files
✅ Detect HDD or SSD
✅ Adjust memory usage
✅ Decrypt files
✅ Generate reports

Progress will appear in the terminal.


step 6
Check Results
After completion, a new folder will be created:
DECRYPTED

also tool genrates some files like
resume_state.jsonl
decrypt_log.txt
recovery_summary.json
recovery_report.csv

| File                  | Purpose                 |
| --------------------- | ----------------------- |
| resume_state.jsonl    | Resume interrupted runs |
| decrypt_log.txt       | Detailed log            |
| recovery_summary.json | Summary statistics      |
| recovery_report.csv   | Per-file results        |


<img width="601" height="174" alt="Screenshot 2026-06-21 150821" src="https://github.com/user-attachments/assets/8d8348bf-e051-4767-9bc2-246aba70f56d" />
<img width="429" height="77" alt="Screenshot 2026-06-21 135921" src="https://github.com/user-attachments/assets/2a79752a-ba46-4af0-824a-ffaac73a0841" />

ERRORS


No module named Crypto
Fix: pip install pycryptodome

No module named filetype
Fix:
pip install filetype

name '_wait_for_ram' is not defined
Fix:Use the latest GitHub release (v1.0.0 or newer).

Access denied
Fix:
Run Command Prompt as Administrator.


This tool is intended only for recovering backups and files you own or are authorized to access.
