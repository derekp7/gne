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
