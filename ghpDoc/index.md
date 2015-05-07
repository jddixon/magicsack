<h1 class="libTop">magicsack</h1>


Magicsack is a utility for storing secret things either locally (on the
laptop or workstation) or over a distributed set of cooperating servers
or on one of the cloud services.

Magicksack is in development using Python 3 on Linux.  This should 
work on Windows as well, but no effort will be made to confirm this
until the development version is stable on Linux.

## Technical Details

Magicksack is protected by a user-selected passphrase.  This is hased
using SHA256 and then the first 256 bits of the hash are used as an AES
key.  When documents are added to the system, the user supplies a unique
name and then the document is AES-encrypted using that key before storage.
It should be possible to generate a different key for each document.  The
index from the user-assigned key to the encrypted document is stored 
locally.  The encrypted documents may be stored locally or on one or more
cooperating servers or on a cloud service or any combination of the 
three.  The index is always AES-encrypted before being stored.  

The system generates two 2048-bit RSA keypairs.  One of these is used
for creating digital signatures; specifically it is used for signing 
the index.  The other is used for encrypting data such as the documents
to be stored in the magicsack.

## Command Line

magicsack init [-f] [-u U_Dir]
magicsack destroy
magicsack add      FILE [FILE]*
magicsack list     [FILE [FILE]*]
magicsack drop     FILE [FILE]*
magicsack addPeer  FQDN[:PORT] [FQDN[:PORT]]*
magicsack listPeer FQDN
magicsack dropPeer FQDN[:PORT] [FQDN[:PORT]]*

### init

This command creates a new local instance, storing information under 
`.magicsack` in the user's home directory.  If the `.magicsack` directory
aleady exists, the command will fail, unless the command line includes
the `-f` option.  Unless otherwise specified data will be stored in 
`.magicsack/uDir`.  If the `-u` option is present data will be stored
in `uDir` instead.

The `init` command asks for a passphrase which then becomes the key 
for all information stored.

This command is destructive.  Any existing information under `.magicsack` 
will be irrevocably deleted.

### destroy

This command erases anything under `.magicsack`.  If `uDir` is not a 
subdirectory of `.magicsack`, `uDir` will be erased if the system permits.

### add

The `add` command adds the files listed.  These are specified using **globs**,
meaning patterns.  So if for example `FILE` is `abc*`, then all local files
whose names begin with `abc` will be added to magicsack.

This is not a destructive operation.  

### list

`list` is followed by zero or more globs.  If there are no globs, then
the entire contents of the magicksack store will be listed.  Otherwise
any file matching the pattern will be listed

### drop

The `drop` command deletes any items matching the file name patter(s)
following from the store.  This action is irrevocable.  

### addPeer

This command adds a remote host (another machine that can be reached 
over the Internet) to the list of cooperating servers.  FQDN may be
either a domain name or an IP address, a **dotted quad** like 1.2.3.4.
Either may optionally be followed by a port number.  


