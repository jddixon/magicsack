# magicSack

**magicSack** is a utility for storing secret things either *locally* (on the
user's laptop or workstation) or
*over a distributed set of cooperating servers* or on one of the
*cloud services* or on some combination of the three.

MagickSack is in development using Python 3 on Linux.  It should
work on Windows as well, but no effort will be made to confirm this
until the development version is stable on Linux.

## Technical Details

MagickSack is protected by a user-selected passphrase.  This is hashed
using SHA256 and then the 256 bits of the hash are used as an AES
key.  When documents are added to the system, the user supplies a unique
name and then the document is AES-encrypted using that key before storage.
It should be possible to generate a different key for each document.  The
index from the user-assigned key to the encrypted document is stored
locally.  The encrypted documents may be stored locally or on one or more
cooperating servers or on a cloud service or on any combination of the
three.  The index is always digitally signed and AES-encrypted before
being stored.

The system generates two 2048-bit RSA keypairs.  One of these, **skPriv**,
is used
for creating digital signatures; specifically it is used for signing
the index.  The other, **ckPriv**, is used for encrypting data while
setting up communications with **peers**, hosts cooperating with
`magicSack` in the storage of documents.

## Command Line

	magicSack init [-f] [-u U_Dir]
	magicSack destroy
	magicSack add      FILE [FILE]*
	magicSack list     [FILE [FILE]*]
	magicSack show     FILE [FILE]*
	magicSack drop     FILE [FILE]*
	magicSack addPeer  FQDN[:PORT] [FQDN[:PORT]]*
	magicSack listPeer FQDN
	magicSack dropPeer FQDN[:PORT] [FQDN[:PORT]]*

Each of these commands asks for the passphrase.  Except in the case
of `init`, if the passphrase is wrong, the command will have no effect.

### init

This command creates a new local instance, storing information under
`.magicsack` in the user's home directory.  If the `.magicsack` directory
aleady exists, the command will fail, unless the command line includes
the `-f` or `--force` option.  Unless otherwise specified documents will be
stored in
`.magicsack/uDir`.  If the `-u` option is present, documents will be stored
in `uDir` instead.

The `init` command asks for a passphrase which then becomes the key
for all information stored.

This command is destructive.  Any existing information under `.magicsack`
will be irrevocably deleted.

If data is to be stored on the cloud, `uDir` **must** be specified and
should be the path to a directory backed up on the cloud.  If that
directory does not exist, `magicSack` will attempt to create it

### destroy

This command erases anything under `.magicsack`.  If `uDir` is not a
subdirectory of `.magicsack`, `uDir` will be erased if the system permits.

This operation is irrevocable.  If the correct passphrase is supplied,
all information on the user's machine relating to the `magicSack`
installation will be erased, unless somehow otherwise protected by
the system.

### add

The `add` command adds the files listed.  These are specified using **globs**,
meaning patterns.  So if for example `FILE` is `abc*`, then all local files
whose names begin with `abc` will be added to magicsack.

This is not a destructive operation.

### list

`list` is followed by zero or more globs.  If there are no globs, then
the entire contents of the magicksack store will be listed.  Otherwise
any file matching the pattern will be listed

The listing contains only information about the document(s) requested,
most importantly the document name (which may be a path) and size,
where the size is the size before encryption.

### show

`show` must be followed by one or more globs.  The contens of any file
whose name or path matches the pattern(s) will be displayed.  In other
words, this information will be sent to `stdout`, which may of course
be directed to a file.

### drop

The `drop` command deletes any items matching the file name pattern(s)
following from the store.  This action is irrevocable.

### addPeer

This command adds a remote host (another machine that can be reached
over the Internet) to the list of cooperating servers.  FQDN may be
either a domain name or an IP address, a **dotted quad** like `1.2.3.4`.
Either may optionally be followed by a port number.

### listPeer

Lists domain name or IP address and port number where the name
matches `FQDN` (a glob).  If `FQDN` is not present on the command line,
all such peers are listed.

### dropPeer

Drops peers matching FQDN from the local list of cooperating peers.  This
should be an eventually destructive act: the remote peers will at some
point remove the data stored there, but there is no guarantee when this
will occur.  (Remember that all data stored remotely is encrypted.)

## Project Status

Pre-alpha.  Some working code, a few tests that succeed.

## On-line Documentation
More information on the **magicsack** project can be found
[here](https://jddixon.github.io/magicsack)
