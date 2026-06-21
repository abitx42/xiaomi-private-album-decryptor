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
