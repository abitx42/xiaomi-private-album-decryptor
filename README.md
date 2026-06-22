# Xiaomi Private Album Decryptor
# Xiaomi Private Album Decryptor

![Python](https://img.shields.io/badge/Python-3.13-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Files Recovered](https://img.shields.io/badge/Files_Recovered-679-success)
![Success Rate](https://img.shields.io/badge/Success_Rate-100%25-brightgreen)
![Release](https://img.shields.io/badge/Release-v1.0.0-orange)

> Recover Xiaomi/POCO Gallery private album backups (.lsa/.lsav) with support for large files, resume functionality, reporting, and low-memory processing.


> Recover Xiaomi/POCO Gallery private album backups (.lsa/.lsav) with support for large files, resume functionality, reporting, and low-memory processing.

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

-Download the Repository
-Download the project from GitHub:
-Code → Download ZIP
-get the zip file from the device contaning .lsa/.lsav files
generally present at
-internal storage> miui > gallery > backup 
if not 
-just search .lsa in search of internal storage and get the location

step 2 
-once check for python version

<img width="1531" height="975" alt="python ver" src="https://github.com/user-attachments/assets/7b9cc370-7ccc-426b-8b54-fc334fbf6ee1" />



-get the zip file in computer

<img width="1404" height="831" alt="filemanager" src="https://github.com/user-attachments/assets/92cb94c0-e0a4-497b-a1cc-d4b1a2e0768e" />

 -unzip file
- it may show error if the fie size is large if it does
- try opening it with 7 zip application

- <img width="1452" height="1001" alt="7zip" src="https://github.com/user-attachments/assets/af9f0eda-459e-465c-95de-35101b095627" />


-download the python file xiaomi_decrypt_adi_v1.0.0_github.

step 3
-open cmd in targeted location

-Install Required Libraries

<img width="922" height="612" alt="require " src="https://github.com/user-attachments/assets/7b6f3d9e-00f8-48e3-8e91-07629ce16ba8" />


-Open Command Prompt inside the project folder.
-Run:
-pip install -r requirements.txt

<img width="1237" height="707" alt="error" src="https://github.com/user-attachments/assets/535904d2-a091-4a54-be71-6f1762067d69" />


-if error occurs check whetther requirements.txt in present in same folder
-Expected output:
-Successfully installed pycryptodome filetype psutil

<img width="1237" height="690" alt="cmd after error" src="https://github.com/user-attachments/assets/14542999-3594-4a65-ab45-d7dcb1c4f472" />


-step 4

-Run The Script
-check once if lsa files are present in coreect path as displayed on cmd
<img width="1608" height="1045" alt="lsa files" src="https://github.com/user-attachments/assets/44751092-f6db-4709-960d-89c1b8a97182" />


-Open Command Prompt in the project folder.
-Run:
python xiaomi_decrypt_adi_v1.0.0_github.py "C:\Backup\secretAlbum"

<img width="1919" height="1079" alt="processing1" src="https://github.com/user-attachments/assets/9141bfd1-85c3-49eb-bce6-5317c199e255" />
<img width="1919" height="1079" alt="processing1" src="https://github.com/user-attachments/assets/be5c3434-ad38-42a7-bc3f-15840e9790a9" />
<img width="1177" height="744" alt="processing" src="https://github.com/user-attachments/assets/0eae681e-7bb1-4748-9ba7-f1edb1341595" />


-Replace the path with your own backup location.

 step 5
- Wait For Processing
<img width="973" height="726" alt="last 2" src="https://github.com/user-attachments/assets/bc0db975-542b-41b1-87c5-0bbabe805011" />
<img width="926" height="597" alt="last" src="https://github.com/user-attachments/assets/5d35e713-f52f-4776-a27d-4be5420bd224" />

The script will automatically:
✅ Scan folders
✅ Detect .lsa and .lsav files
✅ Detect HDD or SSD
✅ Adjust memory usage
✅ Decrypt files
✅ Generate reports

Progress will appear in the terminal.

<img width="973" height="726" alt="last 2" src="https://github.com/user-attachments/assets/6d2d6b65-2429-4abd-a7f8-349eea16b85b" />

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

<img width="601" height="174" alt="sucess" src="https://github.com/user-attachments/assets/df60b071-69b6-49b4-91da-e24338f3139a" />


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
