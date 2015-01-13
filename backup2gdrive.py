#!/usr/bin/python

import os.path
import errno
import sys
import io
import getopt
import getpass
import pprint
import httplib2
import apiclient.discovery
import apiclient.http
import oauth2client.client
from apiclient import errors
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto import Random

################## CONSTANTS

# OAuth 2.0 scope that will be authorized.
# Check https://developers.google.com/drive/scopes for all available scopes.
OAUTH2_SCOPE = 'https://www.googleapis.com/auth/drive'

# Location of the client secrets.
CLIENT_SECRETS = 'client_secrets.json'
ENCRYPTED_OAUTH_TOKEN = 'client_oauth.dat'

# Where to put restored files
RESTORE_PREFIX = 'restored'

################ HELPERS

# Those 3 are only for encryption
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def encrypt(data, crypto_pass):
	crypto_pass = SHA256.new(crypto_pass.encode()).digest()
	data = pad(data)
	iv = Random.new().read( AES.block_size )
	cipher = AES.new( crypto_pass, AES.MODE_CBC, iv )
	enc = iv + cipher.encrypt( data )
	mac = HMAC.new(crypto_pass, enc, SHA256.new(crypto_pass)).digest()
	return (mac+enc)

def decrypt(data, crypto_pass):
	crypto_pass = SHA256.new(crypto_pass.encode()).digest()
	hmac = HMAC.new(crypto_pass, None, SHA256.new(crypto_pass))
	realmac = data[:hmac.digest_size]
	data = data[hmac.digest_size:]
	hmac.update(data)
	if hmac.digest() != realmac:
		print("Invalid password or corrupted data, can't decrypt");
		sys.exit(1) 
	cipher = AES.new(crypto_pass, AES.MODE_CBC, data[:16] )
    	return unpad(cipher.decrypt( data[16:] ))
	
def store_credentials(creds, crypto_pass):
	encrypted_oauth_file = open(ENCRYPTED_OAUTH_TOKEN,'w')
	data = creds.to_json()
	data = encrypt(data, crypto_pass)
        encrypted_oauth_file.write(data)
        encrypted_oauth_file.close()

def read_credentials(crypto_pass):
    encrypted_oauth_file = open(ENCRYPTED_OAUTH_TOKEN,'r')
    encrypted_oauth = encrypted_oauth_file.read()
    encrypted_oauth_file.close()
    oauth = decrypt(encrypted_oauth, crypto_pass)
    return oauth2client.client.Credentials.new_from_json(oauth)

def mkdir_ignore(path):
    try:
        os.mkdir(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

def read_all(path):
    """Reads the content of a local file
    
    Args:
      path: Path of the file to read
    Returns:
      Content of the file
    """
    lfile = open(path,'r')
    data = lfile.read()
    lfile.close()
    return data

def write_file(path, data):
    """Creates or overwrites a local file
    
    Args:
      path: Path of the file to write
    Returns:
      Nothing
    """
    lfile = open(path,'w')
    lfile.write(data)
    lfile.close()
    return

def retrieve_all_files(service, q=""):
  """Retrieve a list of File resources.

  Args:
    service: Drive API service instance.
  Returns:
    List of File resources.
  """
  result = []
  page_token = None
  while True:
    try:
      param = {}
      if page_token:
        param['pageToken'] = page_token
      param['q']=q
      files = service.files().list(**param).execute()
      result.extend(files['items'])
      page_token = files.get('nextPageToken')
      if not page_token:
        break
    except errors.HttpError, error:
      print 'An error occurred: %s' % error
      break
  return result

def backup(path, parent_id):
    if os.path.isfile(path):
        # TODO: Delete remote files with same name if they already exist. Or somehow set a property to only erase our own old backups, not user files
        basename=os.path.basename(path)
        print('Backing up file "'+path+'"...')
        oldfiles = retrieve_all_files(drive, "'me' in owners and title='"+basename+"' and '"+parent_id+"' in parents and trashed=false")
        for oldfile in oldfiles:
            print('Overwriting old version with same name')
            drive.files().delete(fileId=oldfile['id']).execute()
        fh = io.BytesIO(encrypt(read_all(path), crypto_pass))
        body = {'title':basename,'mimeType':"application/octet-stream",'parents':[{'id':parent_id}]}
        media = apiclient.http.MediaIoBaseUpload(fh, mimetype='application/octet-stream',chunksize=-1, resumable=True)
        drive.files().insert(body=body,media_body=media).execute()
        
    elif os.path.isdir(path):
        remotedirs = retrieve_all_files(drive, "'me' in owners and title='"+os.path.basename(path)+"' and '"+parent_id+"' in parents and trashed=false")
        remotedir = None
        if len(remotedirs) == 0:
            body = {'title':os.path.basename(path),'mimeType':"application/vnd.google-apps.folder",'parents':[{'id':parent_id}]}
            remotedir = drive.files().insert(body=body).execute()
        else:
            remotedir = remotedirs[0]
        files = os.listdir(path)
        for file in files:
            backup(path+'/'+file, remotedir['id'])
    else:
        print('Invalid path: "'+path+'", aborting')
        sys.exit(1)

def restore(folderpath, filepath, parent_id):
    #print("Restoring "+filepath)
    filepath = filepath.rstrip(os.sep)
    path_parts = filepath.split(os.sep)
    while path_parts[0] == '' or path_parts[0] == '.':
        path_parts = path_parts[1:]
    if len(path_parts) < 1:
        print('Path splitting failed horribly')
        pprint.pprint(path_parts)
        sys.exit(1)
    elif len(path_parts) > 1:
        dirname = path_parts[0]
        if dirname[:2] == './':
            dirname = dirname[2:]
        remotedirs = retrieve_all_files(drive, "'me' in owners and title='"+dirname+"' and '"+parent_id+"' in parents and trashed=false")
        remotedir = None
        if len(remotedirs) == 0:
            print('Can\'t find directory "'+dirname+'" in parent "'+folderpath+'", aborting')
            sys.exit(1)
        else:
            remotedir = remotedirs[0]
        nextpath = path_parts[1:]
        mkdir_ignore(os.path.join(RESTORE_PREFIX,folderpath,dirname))
        restore(os.path.join(folderpath,dirname), os.path.join(*nextpath), remotedir['id'])
    else:
        filepath = path_parts[0]
        files = retrieve_all_files(drive, "'me' in owners and title='"+filepath+"' and '"+parent_id+"' in parents and trashed=false")
        rfile = None
        if len(files) == 0:
            print('Can\'t find file "'+filepath+'" in parent "'+folderpath+'", aborting')
            sys.exit(1)
        else:
            rfile = files[0]
        if rfile['mimeType']=="application/vnd.google-apps.folder":
            mkdir_ignore(os.path.join(RESTORE_PREFIX,folderpath,filepath))
            rdir = rfile
            #print('Restoring folder "'+filepath+'"...')
            files = retrieve_all_files(drive, "'me' in owners and '"+rdir['id']+"' in parents and trashed=false")
            for rfile in files:
                restore(os.path.join(folderpath,filepath), rfile['title'], rdir['id'])
        else:
            print('Restoring file "'+os.path.join(folderpath,filepath)+'"...')
            download_url = rfile.get('downloadUrl')
            if download_url:
                resp, content = drive._http.request(download_url)
                if resp.status == 200:
                    write_file(os.path.join(RESTORE_PREFIX,folderpath,filepath), decrypt(content, crypto_pass))
                else:
                    print 'An error occurred while restoring: %s' % resp
                    return None
            else:
                write_file(os.path.join(RESTORE_PREFIX,folderpath,filepath), '')
    

########################## MAIN LOGIC

# Parse args
backuppath = ""
restorepath = ""
try:
    opts, args = getopt.getopt(sys.argv[1:],"hcb:r:",["help","clear-auth","backup=","restore="])
except getopt.GetoptError:
    print 'backup2gdrive.py [-h, --help] [-c, --clear-auth] [-b, --backup <localpath>] [-r, --restore <remotepath>]'
    sys.exit(2)
for opt, arg in opts:
    if opt in ("-h", "--help"):
        print 'backup2gdrive.py [-h, --help] [-c, --clear-auth] [-b, --backup <localpath>] [-r, --restore <remotepath>]'
        sys.exit(0)
    elif opt in ("-b", "--backup"):
        backuppath = arg
    elif opt in ("-r", "--restore"):
        restorepath = arg
    elif opt in ("-c", "--clear-auth"):
        print('Clearing our local auth token. You will need to grant the permissions again next time')
        try:
            os.remove(ENCRYPTED_OAUTH_TOKEN)
        except:
            pass
        sys.exit(0)

if backuppath == "" and restorepath == "":
    print 'backup2gdrive.py [-h] [-b, --backup <localpath>] [-r, --restore <remotepath>]'
    sys.exit(0)

# Get our encryption password
crypto_pass = getpass.getpass('Enter password: ')

# Use OAuth to create an authorized Drive API client.
creds = None
if os.path.isfile(ENCRYPTED_OAUTH_TOKEN):
	creds = read_credentials(crypto_pass)
	print('Credentials loaded successfully')
else:
	flow = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRETS, OAUTH2_SCOPE)
	flow.redirect_uri = oauth2client.client.OOB_CALLBACK_URN
	authorize_url = flow.step1_get_authorize_url()
	print('Go to the following link in your browser: ' + authorize_url)
	oauth_token = raw_input('Enter verification code: ').strip()
	creds = flow.step2_exchange(oauth_token)
	store_credentials(creds, crypto_pass)
http = httplib2.Http()
creds.authorize(http)
drive = apiclient.discovery.build('drive', 'v2', http=http)
print('Connected to Google Drive')

# Open/create our backup dir in drive
files = retrieve_all_files(drive, "'me' in owners and title='backup' and 'root' in parents and trashed=false")
baakdir = None
if len(files) == 0:
	print('No backup folder found, creating one')
	bakdir = drive.files().insert(body={'title':"backup",'mimeType':"application/vnd.google-apps.folder"}).execute()
else:
    bakdir = files[0]

# TODO: Ask whether we want to backup or to restore
# In both cases we take a path to a file/folder and transfer all of it
# For now if we try to backup a file that already exists, overwrite it. Later learn to check the last modified times

if backuppath != "":
    print('Backing up "'+backuppath+'"')
    backup(backuppath, bakdir['id'])

if restorepath != "":
    print('Restoring "'+restorepath+'" in "'+RESTORE_PREFIX+'"')
    mkdir_ignore(RESTORE_PREFIX)
    restore("", restorepath, bakdir['id'])
    
