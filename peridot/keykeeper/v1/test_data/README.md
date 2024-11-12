# Notes on test data

## GPG Keys

> **Warning**
>
> Set `GNUPGHOME` to `$PWD/.gnupg` or allow `direnv` on this directory.
>
> The key(s) in this directory should never be used for any serious purpose. They exist to test and verify signatures of
> various types.

The passphrase for the encrypted key is "the same as the UUID in the KeysDB map. This is how KeyKeeper encrypts keys it
imports.

## Changing GPG data

Make sure you run `gpgconf --kill all` before committing anything if you open or change the .gnupg data.

## RPMS

### Signme RPMS

These rpms have all signatures, but not digests removed. c7 rpms are present because they represent a different RPM
Header version than later RPM versions use. We want to ensure that CentOS 7 rpms can still be signed correctly with
KeyKeeper, and modern RPM versions.

### Verifyme RPMS

These rpms have been signed with the KeyKeeper Signing Key. They are for verifying test setup, and for comparing with
Signme RPMS.

### Useful RPM commands

Show all headers

```
(for i in `rpm --querytags`; do rpm -qp --queryformat="${i} == %{${i}}\n" example.rpm; done) | less
```
