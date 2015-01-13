# backup2gdrive
Encrypted backups to Google Drive

A simple script to backup and restore encrypted files in a Google Drive folder.<br/>
The files are encrypted with AES CBC using the SHA256 of the password, and authenticated with HMAC-SHA256<br/>
Filenames are not encrypted, all other metadata is lost.<br/>

This script is restricted to Python 2, because google's drive api still uses Python 2.

<h3>Usage:</h3>
<pre>
backup2gdrive.py [-h, --help] [-c, --clear-auth] [-b, --backup <localpath>] [-r, --restore <remotepath>]

Options:
  -h, --help: Show usage
  -c, --clear-auth: Removes our local credentials, you will need to grant permissions again
  -b, --backup <localpath>: Encrypts and upload <localpath> to Google Drive. Can be a file or folder.
  -r, --restore <remotepath>: Downloads and decrypts <remotepath> from Google Drive. Can be a file or folder.
</pre>

<h5>Boring details</h5>
Uploaded files are stored in a folder called "backup" in Google Drive, and will overwrite any previous files with the same name so don't use this script if you already have a folder called "backup" with important things inside... 
Restored files are downloaded to "./restored/", and will also overwrite any previous files with the same name.
You will need to grant full Google Drive permissions to the script on first run on the target account, this requires a web browser. The credentials are stored encrypted on disk after first use, with the same encryption used for the files.
I totally just uploaded my google client secret and id with the script to make it simpler.
This comes with no warranty of any kind, especially not fitness for any particular purpose. Slippery when wet.
