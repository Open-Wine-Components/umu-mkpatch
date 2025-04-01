# umu-mkpatch
Generate patch files from umu compatibility tools.

## Description
This program is a simple patch generator, and the patch files generated are intended to be consumed by [umu-launcher](https://github.com/Open-Wine-Components/umu-launcher) with umu-supported compatibility tools as inputs. The generated patch file is bit inspired from Mozilla's [MAR](https://wiki.mozilla.org/Software_Update:MAR) format. However, different decisions are made for the file's serialization format, cryptographic primitives, and patch engine to create the binary diffs.

## Usage
At a high level, `umu-mkpatch` compares two directories, where 'a' and 'b' contain similar file hierarchies, then produces a file containing both the metadata and data necessary to recreate 'b' both quickly and securely.

Assuming GE-Proton9-20 and GE-Proton9-21 are installed in the Downloads folder, and the user has Ed25519 `ssh(1)` keys:

```
$ cd python/umu_mkpatch
$ python __main__.py --source $HOME/Downloads/GE-Proton9-20 --target $HOME/Downloads/GE-Proton9-21 --ssh-private-key $HOME/.ssh/id_ed25519 --ssh-public-key $HOME/.ssh/id_ed25519_.pub > delta.cbor
```

> [!NOTE]
> The SSH keys are used to sign and verify the patch data. Only the public key will be shared in the patch file, and it must not be password-protected.
