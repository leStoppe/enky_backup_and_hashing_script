Intro
======

Enky is a python3 script that leverages 7z binary to do two main functions:

 1. Backups (full, incremental, decremental)
 2. Recursive file hash and check

The name is based off a typo of Enki, the Sumerian god of crafts/knowledge. Got inspired to use this name as a knowledge keeper.

Installation
=============

1. Install python x64 (<https://www.python.org/downloads/>)
2. Install 64 bit 7zip (<https://www.7-zip.org/>)
3. Install the Text Table python module. Windows + R, cmd (pip install texttable)
4. Update the encryption password in the Enky script.
5. (Optional) Update the path to 7z.exe in the Enky script if 7zip was intalled to a non standard path

Useful commands
================

1. view help
    ``` bash
    python .\enky_backup_checksum.py -h
    ```

2. create a full backup of "target_dir" and store it in "backup_loc". (Use a separate backup_loc for different target_dir)
    ``` bash
    python .\enky_backup_checksum.py backup -bc -bf -bl backkup_loc -bt target_dir
    ```

3. Updating backup with new changes:

    1. Updates add new changes from "target_dir".

    2. The bacup_loc retains old backup history. So it's possible to restore to a specific version of the backup.

    3. The updates can be done in either differential or incremental fashion. They can't be mixed.

    4. create an incremental backup of "target_dir". Incremental backups can be made only after an intiail full backup

        ```bash
        python .\enky_backup_checksum.py backup -bc -bi -bl backkup_loc -bt target_dir
        ```

    5. create a differential backup of "target_dir".

        ```bash
        python .\enky_backup_checksum.py backup -bc -bd -bl backkup_loc -bt target_dir
        ```


4) Viewing available backups at backup_loc

    ```bash
    python .\enky_backup_checksum.py backup -bv -bpv -bl backkup_loc
    ```

5) Restoring a specific backup. #number is the index of the version seen from the previous command. This will restore data to target_dir
    ``` bash
    python .\enky_backup_checksum.py backup -br -brn #number -bl backkup_loc -bt target_dir
    ```

6. Creating checksums of a directory

    1. This will recursively examine all files within the "hash_target" directory and store checksums in a "hash_file"

    2. The goal is to detect bit rot and silent data corruption of files

    3. The command:

        ```bash
        python .\enky_backup_checksum.py checksum -hs -ht hash_target -hf hash_file
        ```

7. Checking file checksums3

   1. This will verify the checksums of all files within the "hash_target" that have a hash previously created in "hash_file"

   2. Files that got changed/corrupted and deleted will be detected. Newly added files will not be discovered.

   3. The command:

      ```bash
      python .\enky_backup_checksum.py checksum -hc -ht hash_target -hf hash_file
      ```

      Additional notes:


Backups
========

 1. The tool creates encrypted and slighly compressed 7z archives as full / partial backups. The dependency
is Python3 and 7z, so it should work in Linux too but it's primarily tested on windows.

 2. Full backups take the entire set of source files and archives them. Both incremental and decremental
backups have a base variant that a full backup. DO NOT MIX.

 3. Incremental backups only store the difference between the new state and the previous backup. It
occupies less space but to restore every backup till the target date needs to be parsed. The latest backup here is
the full backup while the incremental archives store the delta needed to restore to an older state.

 4. Decremental backups store the difference between the original full backup and the current state. They
require only two archives (the original full backup plus the backup at the target date) BUT occupies more space.
There is also more redundancy. The oldest backup here is the full one. Every other one is a direct delta from this
base.

Hashcheck
==========

 1. In this mode, the script walks through the target directory, computes the sha256 for every file found
and stores in a test file. To check, it'll go through the text file, recompute the hash and compare. NOTE, while
checking, it'll skip any new files that were added.

Misc
=====

1. The encryption key is stored in the script as plaintext for convenience. I generally dislike using passwords
    in a backup but given how there is some likelyhood of data breeches in cloud storage or when a failed backup-hardisk
    might get sold/RMAd/refurbished, it seemed prudent to have a basic encryption-at-rest scheme.
2. From experience, it's best to have 3 backups in additional to the original copy. Two in physically separate,
    normally disconnected local media ( hard drives, USB flash drives, dvds etc) and a third one offsite, on the cloud
    (backblaze or onedrive). It was also suggested to keep the two local copies in different media types to account for
    the different archival qualities of different media but I've found it to be a hassle when the data size is huge.
3. When storing on DVDs or on the cloud, use 7zip to archive the backup directory in split volume mode. This is
necessary obviously for media that has smaller capacity than what's needed. This is also helpful when uploading to
the cloud; when the network breaks down and something needs to be retransmitted, it's best to have it in smaller chunks.
