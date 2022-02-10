# Tar Genie
> A tar compatible archiver with public key encryption

Tar Genie (`gne`) is a new implementation of the Unix `tar` program that includes encryption extensions.  When specified with the `-e` (`--encrypt`) flag, the overall tar format is maintained, with the individual archive members' contents encrypted using the specified public key file.

* [Full man page](#gne1---Implementation-of-tar-with-public-key-encryption-extensions)
* [File format](#gne5---format-of-gne-extensions-to-tar)

## Compile:
Requires OpenSSL 1.1.x and lzo2 libraries

    gcc -std=c99 gne.c tarlib.c -l crypto -l ssl -l lzo2 -o gne -DXATTR

(Leave off "-DXATTR" if your OS doesn't support listxattr() / setxattr() calls)

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

## Mini FAQ
- *What is the difference between this, and piping a tar archive through openssl or gpg?*

The traditional method of encrypting a tar file produces a completely opaque output encrypted file.  You can't perform a directory listing or pull any other metadata from it (which may be desirable for some limited circumstances, such as if the file names or sizes are sensitive information), however if used as part of an overall backup strategy the metadata may be needed.  Think of it as similar to the functionality of an encrypted *.zip* archive.

Another benefit is that the RSA keyfile used to encrypt the archive is included in the header (with the private key passphrase protected), so all you need to provide is a password to decrypt the tar file.  Yet when backing up, no password/passphrase is required.

- *Is there any security concerns to leave the encryption keyfile on the computer?*

Not a concern for confidentiality, as the keyfile uses an RSA Public key to encrypt, and the Private key is stored encrypted with your chosen passphrase.  However the keyfile does contain an HMAC key used to generate the verification hash of the encrypted archive members.  So the keyfile should still be protected so that alterations of the encrypted tar members can be detected.

- *What is with the name?*

Since the primary purpose of *gne* is to encrypt, the name was chosen by applying ROT13 encryption to the name *tar*.  (Don't worry, the encryption actually employed by *gne* is much stronger than ROT13).

- *How does verification work?*

An HMAC hash is generated of the public key using the provided private key as the HMAC key.  This resulting hash is used as the HMAC key for computing the verification hash.  Note that the HMAC key is not recorded in the generated *tar* file -- 
it is instead re-created using the public key and the user-supplied password when extracting files from the archive.

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

## Description

The **gne** command creates and extracts _tar_ files, with many of the common format extensions from _GNU tar_ and _POSIX pax_ formats.  In addition, _gne_ adds new extensions that cover recording _public key encryption_ related parameters.  When used with the [**-k**|**--encrypt** _KEYFILE_] flag, the public key recorded in _KEYFILE_ is used to encrypt a randomly generated _AES256_ key, which is then used to encrypt an archive member, after applying data compression to the source file.  The passphrase-protected (encrypted) private key in the _KEYFILE_, along with the public key and other parameters, are recorded in the _tar_ file's global header.  Upon extraction, the passphrase will be prompted for, which unlocks the private key, allowing decryption and extraction of the data.  This allows for encrypted backups to be taken without needing to enter a passphrase or key, and the passphrase is only needed at the time of key creation and during file extraction operations.

<a name="options"></a>

## Options


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
* **-C**, **--directory** _DIRECTORY_  
  Changes to _DIRECTORY_ before performing any operations.
* **-P**, **--absolute-names**  
  Do not strip out leading "/" on path names when extracting archive.
* **--one-file-system**  
  Restricts directory descent to directory's current file system (don't cross mount points).
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
      Can be specified multiple times.  Sends the archive output to _PROGRAM_, which may be specified with parameters.  If specified more than once, the archive is split up on file boundaries into multiple streams, in a round-robin fashion, skipping over a stream if it is still busy.  The environment variable **GNE_STREAM_ID** is set to a numeric value identifying the stream, starting with 1.  Also the environment variable **GNE_VERBOSE** is set to "1" if the verbose flag was specified.
    * **SESSIONID** _SESSION ID_  
      Sets the environment _GNE_SESSIONID_ to the given _SESSION ID_ when launching the programs specified in _STREAMPROG_ or _MANIFEST-FILTER_.
    * **BEGIN_FEEDBACK**  
      Begins feedback mode, where each line of output is displayed, and normal feedback from _gne_ is suppressed.
    * **BEGIN_STREAMPROG_FEEDBACK**  
      Specifies that the output of STEAMPROG is displayed, and normal feedback from _gne_ is suppressed.
    * **USERVAR** _VARNAME_ _Value_  
      Sets an environment variable name composed of 'GNE_USERENV_' followed by _VARNAME_  to be set to the contents of _Value_ when calling _MANIFEST-FILTER_ and _STREAMPROG_.  Useful for setting a session ID variable.

<a name="format-notes"></a>

## Format Notes

When required, output is in PAX format, utilizing custom PAX variables.  In addition, since tar is a streaming archiver, normally the tar format requires knowledge of the size of the member as it appears in the archive.  This would normally make it impractical to apply compression/encryption or any other transformation to files while writing to the archive, as the final encoded size wouldn't be known unless two passes are made.  To solve this, data is written to an in-memory buffer when being encoded.  If the end of the input file is reached prior to the buffer becoming full, then the file path remains the same, and header information is generated/written out, followed by the encoded file contents.  However, if the buffer fills, then the file path is converted to a directory name, followed by a file name reflecting the segment number.  For example, an input file /data/foo becomes /data/foo/part.00000000, /data/foo/part.000000001, etc.  The on extraction, these are automatically recombined as needed.  This means that if extracting with a non-compatible tar utility, those files can be combined and decoded manually to recreate the original data.

Full details are in the gne.5 manpage.

---

# gne(5) - format of gne extensions to tar

File Formats, December 2021


<a name="description"></a>

## Description

**gne** is a general tar compatible archiver with extensions supporting public key encryption of compressed archive members, along with other enhancements such as virtual file support.  The format follows the Unix tar layout with pax and GNU tar extensions.  Additional extensions that support gne-specific features are recorded in custom pax header variables as described below.

Familiarity with the standard tar format with pax extensions is useful for understanding this document.  The man(5) page for GNU tar will give a sufficient overview, along with other online documentation (such as the Wikipedia entry on tar).  However a brief summary follows.

A tar file consists of one or more archive members (individual files contained within the tar file).  Each member has a 512-byte header containing metadata (such as file name, ownership, permissions, timestamps, file type, and size of the file).  The data comprising the individual member files follows this 512 byte header, in 512-byte blocks with the last block padded with null characters if needed.  There have been numerous extensions that pack more metadata into this 512 byte header that support file names, sparse files, additional timestamps, etc.  These may vary from one vendor tar implementation to another.

The POSIX pax format was introduced to allow for an arbitrary number of  additional metadata items.  This consists of a 512-byte tar header block, with the file following it containing key/value pairs describing the additional metadata.  This is then followed by a standard tar file member block (512-byte header followed by file contents).  It is in these key/value members that the gne extensions are recorded.

One key item to note is that since tar is a streaming format, it requires that a member file size be known and recorded in the header block before the contents is written out.  So this is why compression (and encryption and other transformations) are typically applied outside of the tar creation process on the whole tar file, and not individual members.  This results in an output file that is not a tar file, but it is an encrypted file containing a compressed file, containing a tar file.  So you can't perform any operations on the tar file contents without decrypting and decompressing it first.

If you are applying transformations (such as compression prior to encryption) to an archive member first, then recording it, then you can write the member file out to a temporary file first in order to obtain the final size.  This will require additional temporary space (which may not be available), and additional CPU and disk I/O resources increasing archive file creation time.  Another option is to perform two passes, such as what GNU tar does when recording sparse files.  Again this takes additional time.

The solution that gne uses is to apply streaming compression / encryption to an archive member file and record the results into segments in the resulting tar archive.  So for example a file with the name of /somewhere/foo will be written out as /somewhere/foo/part.0001 followed by /somewhere/foo/part.0002, followed by ..., withe the first part marked as the beginning of a segmented file entry (via a custom pax key/value entry preceding the part), and the final part marked as the final segment (via another pax key/value entry).  This allows the data transformation to be performed in a streaming fashion, with results recorded in a memory block (default 1M), and the contents of that block dumped to a .../part.xxxx file when it is filled.

<a name="global-header"></a>

### Global header

A gne tar file starts with a pax global header.  This contains the public/private key information from the key file (generated with "gne -E keyfile.key").  The pax variables used are recorded with vendor prefix "TC.", as the file format is taken from the tarcrypt component of the SNEBU backup system.  They are as follows:

* TC.version  
  Contains the file format version.
* TC.pubkey.fingerprint  
  Fingerprint of the RSA public key component.
* TC.eprivkey  
  Encrypted RSA private key from the key file.
* TC.pubkey  
  Public key from the key file.
* TC.hmackeyhash  
  SHA256 hash ofr the HMAC secret key used in the hmac signatures associated with each encrypted archive member.
* TC.keyfile.comment  
  Comment field from the key file used to encrypt the archive members.
  
  If more than one key file is used, then additional variables is specified:
* TC.numkeys  
  number of encryption keys specified.
* TC.keygroups  
  Comma delimited list of pipe-delimited key group tuples used in encrypted archive members.  Example:
  
      TC.numkeys=3
      TC.keygroups=0|1,0|2
  
  This specifies that 3 encryption keys are represented, and there are files that in the archive that are encrypted with keys 0 and 1, and other files encrypted with keys 0 and 2.
Also, when multiple encryption keys are represented, the key specification headers (TC.pubkey.fingerprint, TC.eprivkey, TC.pubkey, TC.hmackeyhash, TC.keyfile.comment) are represented once for each key, with an index number appended (i.e., "TC.eprivkey.0", "TC.eprivkey.1", etc).  Normally there would just be one keygroup, however other tools may synthesize a tar file with encrypted members from multiple sources.

<a name="archive-member-headers"></a>

### Archive member headers

Each encrypted archive member is preceded by a pax header with the following 

* TC.cipher  
  Cipher method used.  Currently supported is rsa-aes256-ctr.
* TC.compression  
  Compression method applied prior to encryption.
* TC.keygroup  
  Used only if multiple keys are present.  Contains a pipe-delimited numeric list of keys used to encrypt this file.  When multiple keys are used, only one key is needed to decrypt the file.
* TC.segmented.header  
  Indicates a multi-part file entry follows.
  If an archive member file size isn't known ahead of time, and ends up being more than the buffer size (default 1 MiB), "TC.segmented.header" is set (with a value of "1"), and what follows a series of archive members with names in the format "file/path/part.xxxxxxxxx".  The "xxxxxxxxx" is replaced by an increasing segment number.  These file names aren't processed during decoding, however they are present in case the archive is extracted using a standard tar implementation.  In that case, upon extraction the original file will be replaced with a directory of the same name, and the contents of that directory can be combined, then decrypted manually to reconstruct the original data.
* TC.segmented.final  
  Used to indicate the last entry in a multi-part file.
* TC.original.size  
  Indicates the original size of the raw input file.
  If the input file size is not known at the beginning of encoding (such as the case when virtual files are specified), then this value appears in the pax header of the final segment.

<a name="encrypted-data-format"></a>

## Encrypted Data Format


Each encrypted archive member is encrypted with 256-bit AES in CTR mode, using a randomly generated 256-bit key.  This key is in turn encrypted by each of the specified RSA public keys from the given key file(s).  The encrypted data stream begins with a 32-bit number (4 bytes) in network byte order representing the number of encryption keys used.  This is followed by another 32-bit number with the length of the first RSA-encrypted AES key, followed by the key itself.  These are repeated for each RSA key specified.  The encrypted data stream follows the final RSA-encrypted AES key.

<a name="rationale"></a>

## Rationale


Typically when encryption or other transformation (such as data compression) is required on a tar file, the tar file as a whole is compressed / encrypted as a separate stage.  The resulting file can't be processed as a tar file (i.e., pulling a file listing from the archive) without first decrypting  / decompressing the contents.  This ends up being unsuitable for use with archive management tools that require access to the metadata contents, unless the metadata is conveyed separately.  These cases which involve processing of the tar file without prior decryption would require that the archive member files be individually encrypted before being placed in the tar archive, along with additional tar metadata indicating the encryption specifics.

When compression is also applied prior to encrypting, then the final resulting file size isn't known until the end of the operation.  This poses a problem for tar archives, as the size of the encoded data must be known up front.  The solution that gne uses is to logical break a file up into multiple segments.  So a file path such as /foo/bar becomes /foo/bar/part.000000001, followed by /foo/bar/part.000000002, etc. with each segment limited to the size of an internal buffer (default 1 MB).  So as the file stream is being compressed and encrypted, the results start getting dumped into a buffer, and when that buffer fills it is written out as an archive member.  The first segment is labeled as the beginning of a segmented file series, and the last segment is identified as such through extended pax header entries which allows the segments to be recombined into the original file upon extraction.  This technique also enables the use of having tar member file data to be generated on the fly by an external process, such as performing a database dump (using the --virtual-file flag).

If a multiple-segment entry is extracted using a standard tar utility, the individual segments appear as above, and can be recombined manually after extraction.  Further, the passphrase-protected (encrypted) RSA private key can be manually extracted from the global header and used with the openssl command line tool to decrypt then entry.
