# Tar Genie
> A tar compatible archiver with public key encryption

Tar Genie (`gne`) is a new implementation of the Unix `tar` program that includes encryption extensions.  When specified with the `-e` (`--encrypt`) flag, the overall tar format is maintained, with the individual archive members' contents encrypted using the specified public key file.

## Mini FAQ
- *What is the difference between this, and piping a tar archive through openssl or gpg?*

The traditional method of encrypting a tar file produces a completely opaque output encrypted file.  You can't perform a directory listing or pull any other metadata from it (which may be desirable for some limited circumstances, such as if the file names or sizes are sensitive information), however if used as part of an overall backup strategy the metadata may be needed.  Think of it as similar to the functionality of an encrypted *.zip* archive.

Another benefit is that the RSA keyfile used to encrypt the archive is included in the header (with the private key passphrase protected), so all you need to provide is a password to decrypt the tar file.

- *Is there any security concerns to leave the encryption keyfile on the computer?*

Not a concern for confidentiality, as the keyfile uses an RSA Public key to encrypt, and the Private key is stored encrypted with your chosen passphrase.  However the keyfile does contain an HMAC key used to generate the verification hash of the encrypted archive members.  So the keyfile should still be protected so that alterations of the encrypted tar members can be detected.

- *What is with the name?*

Since the primary purpose of *gne* is to encrypt, the name was chosen by applying ROT13 encryption to the name *tar*.  (Don't worry, the encryption actually employed by *gne* is much stronger than ROT13).

- *How does verification work?*

An HMAC hash is generated of the public key using the provided private key as the HMAC key.  This resulting hash is used as the HMAC key for computing the verification hash.  Note that the HMAC key is not recorded in the generated *tar* file -- 
it is instead re-created using the public key and the user-supplied password when extracting files from the archive.

## Compile:

    gcc gne.c tarlib.c -l crypto -l ssl -l lzo2 -o gne

## Examples

### Generating a key file

    $ gne -E mysecret.key --keycomment "Office Workstation Key"
    Enter passphrase: [ input hidden ]
    Verifying - Enter passphrase:  [ input hidden ]

### Creating an encrypted tar file

    $ gne -e mysecret.key -cvf home_backup.tar /path/to/files

### Extracting files

    $ gne -xvf home_backup.tar
    Need a passphrase for one of the following key(s):

    Fingerprint: QtIgfNdqA/UlbstUp2NXJAbn2wJjYG+esi6boH+Loy4=
    Source: derekp@derekp-home2
    Date: 2021/12/23 23:51:46
    Comment: Office Workstation Key

    Enter passphrase: [ input hidden ]

### MAN page follows
Note, that this is a work in progress.  Many items documented in the man page are not implemented yet, but should appear before the initial release.

---

# gne(1) - Implementation of tar with public key encryption extensions

gne, December 2021


<a name="common-commands"></a>

### Common Commands

```
gne -K KEYFILE 
gne -c [OPTIONS] [-k KEYFILE] [-f ARCHIVE] [FILE...] 
gne -x [OPTIONS] [-f ARCHIVE] [MEMBER...] 
gne -d [OPTIONS] [-f ARCHIVE] [FILE...] 
gne -t [OPTIONS] [-f ARCHIVE] [MEMBER...] 

```

<a name="description"></a>

# Description

The **gne** command creates and extracts _tar_ files, with many of the common format extensions from _GNU tar_ and _POSIX pax_ formats.  In addition, _gne_ adds new extensions that cover recording _public key encryption_ related parameters.  When used with the [**-k**|**--encrypt** _KEYFILE_] flag, the public key recorded in _KEYFILE_ is used to encrypt a randomly generated _AES256_ key, which is then used to encrypt an archive member, after applying data compression to the source file.  The passphrase-protected (encrypted) private key in the _KEYFILE_, along with the public key and other parameters, are recorded in the _tar_ file's global header.  Upon extraction, the passphrase will be prompted for, which unlocks the private key, allowing decryption and extraction of the data.  This allows for encrypted backups to be taken without needing to enter a passphrase or key, and the passphrase is only needed at the time of key creation and during file extraction operations.

<a name="options"></a>

# Options


<a name="primary-arguments"></a>

### Primary arguments

Specify only one of the following upon command invocation.

* **-c**, **--create** _FILE_ [_FILE..._]  
  Creates a new _tar_ archive.  _FILE_[_..._] can specify a list of one or more files or directories.  Directories will be recursively included unless specified otherwise.
* **-x**, **--extract** [_FILE_ [_FILE..._]]  
  Extracts members from a _tar_ archive.  Default is for all members to be extracted, otherwise only the _FILE(s)_ specified will be processed.
* **-d**, **--diff** [_FILE_ [_FILE..._]]  
  Compares members from a _tar_ archive to files on disk..  Default is for all members to be compared, otherwise only the _FILE(s)_ specified will be processed.
* **-t**, **--list** [_FILE_ [_FILE..._]]  
  Displays a table of contents of a _tar_ archive.  Similar to _-x_ (_--extract_), default is to list all files unless specific files or directories are specified.
* **-E**, **--genkey** _KEYFILE_  
  Generates a public key encryption key file

<a name="additional-arguments"></a>

### Additional arguments

The following are used in conjunction with one or more of the Primary options

* **-v**, **--verbose**  
  When used with _-c_ (_--create_), _-x_ (_--extract_), or _l-d_ (_--diff_), the member file name(s) will be displayed.  When used with _-t_ (_--list_), additional metadata (permissions, owner, size, date) will also be displayed.
* **-e**, **--encryptkey** _KEYFILE_  
  When used with _-c_ (_--create_), files are compressed, then encrypted using the RSA key in _KEYFILE_ to encrypt a random AES key, which in turn is used to encrypt the archive member.  If the compressed & encrypted file is larger than _segment size_, the file will appear in the archive as a multi-segment file (see below).

When specified multiple times, _KEYFILE_ the random AES key is encrypted with each RSA key in the specified _KEYFILEs_.  This allows the use of a backup key in case the passphrase for the primary one is lost.

* **--passhprase** _PASSPHRASE_  
  Optionally specify a passphrase on the command line.  If the passphrase matches one used to encrypt one of the RSA private keys in _KEYFILE_, it will be used instead of prompting for one.  Can be specified multiple times to provide multiple passphrases to try.
* **--keycomment** _COMMENT_  
  Used with _-E_ (_--genkey_), optionally provides a comment to be recorded in the _KEYFILE_.
* **-T, --files-from** _FILE_  
  Process files from the given _FILE_ instead of the command line.  The _FILE_ is a list of file paths delimited with newlines.  Add the _--null_ option to use a file delimited with null characters.
* **--virtual-file** _PATH_[_PERMISSION_,_OWNER_,_GROUP_]=_PROGRAM_  
  Executes the given _PROGRAM_, using its output to appear in the archive as file name _PATH_.  If the size of the output stream of _PROGRAM_ is larger than _segment size_, the file will appear in the archive as a multi-segment file (see below).
* **--segment-size** _NUMBER_  
  Sets the segment size of segmented files.
* **--exclude** _PATTERN_  
  Exclude files matching the pattern specified by _PATTERN_.

<a name="external-backup-program-integration"></a>

### External backup program integration


* **--external-backup-init** _PROGRAM_  
  When used with _-c_ (_--create_), calls the given PROGRAM to initialize an external backup system.  The program may generate on its output a number of parameters, including:
    * **MANIFEST-FILTER** _PROGRAM_  
      Sends the list of files to back up to the given _PROGRAM_, which may be specified with parameters.  This causes _gne_ to send the list of included files to the specified program, which returns a manifest of actual files to back up.  Files included in the archive will be the output of this program.  This is useful for performing snapshot or incremental backups where the external program manages backup sets.  By default, the output is newline-delimited.
    * **MANIFEST-FILTER-FORMAT** [**LF**|**NULL**]  
      Sets the expected output format of _MANIFEST-FILTER_.  If _LF_ (newline) is specified, files are delimited by a newline (linefeed) character (ASCII 10), and backslash-escapes are processed.  If _NULL_ is specified, filenames are null-delimited and no backslash-escapes are processed.
    * **STREAMPROG** _PROGRAM_  
      Can be specified multiple times.  Sends the archive output to _PROGRAM_, which may be specified with parameters.  If specified more than once, the archive is split up on file boundaries into multiple streams, in a round-robin fashion, skipping over a stream if it is still busy.  The environment variable **GNE\_STREAM\_ID** is set to a numeric value identifying the stream, starting with 1.  Also the environment variable **GNE\_VERBOSE** is set to "1" if the verbose flag was specified.
    * **SESSIONID** _SESSION ID_  
      Sets the environment _GNE\_SESSIONID_ to the given _SESSION ID_ when launching the programs specified in _STREAMPROG_ or _MANIFEST-FILTER_.
    * **BEGIN\_FEEDBACK**  
      Begins feedback mode, where each line of output is displayed, and normal feedback from _gne_ is suppressed.
    * **BEGIN\_STREAMPROG\_FEEDBACK**  
      Specifies that the output of STEAMPROG is displayed, and normal feedback from _gne_ is suppressed.
    * **USERVAR** _VARNAME_ _Value_  
      Sets an environment variable name composed of 'GNE_USERENV_' followed by _VARNAME_  to be set to the contents of _Value_ when calling _MANIFEST-FILTER_ and _STREAMPROG_.  Useful for setting a session ID variable.

<a name="format-notes"></a>

# Format Notes

When required, output is in PAX format, utilizing custom PAX variables.  In addition, since tar is a streaming archiver, normally the tar format requires knowledge of the size of the member as it appears in the archive.  This would normally make it impractical to apply compression/encryption or any other transformation to files while writing to the archive, as the final encoded size wouldn't be known unless two passes are made.  To solve this, data is written to an in-memory buffer when being encoded.  If the end of the input file is reached prior to the buffer becoming full, then the file path remains the same, and header information is generated/written out, followed by the encoded file contents.  However, if the buffer fills, then the file path is converted to a directory name, followed by a file name reflecting the segment number.  For example, an input file /data/foo becomes /data/foo/part.00000000, /data/foo/part.000000001, etc.  The on extraction, these are automatically recombined as needed.  This means that if extracting with a non-compatible tar utility, those files can be combined and decoded manually to recreate the original data.

Full details are in the gne.5 manpage.

