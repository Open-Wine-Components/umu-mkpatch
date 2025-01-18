import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha512
from io import BufferedRandom
from pathlib import Path

from cbor2 import CBORTag, dump, dumps, load

from ._builder import Builder
from ._types import CustomDataItem, CustomDataItemContainer
from ._util import compare_directories, get_versioned_subdirectories
from .umu_mkpatch import ssh_sign, ssh_verify

# CBOR tag used to create a file identified as CBOR by the Linux file utility
# https://www.rfc-editor.org/rfc/rfc8949.html#self-describe
CBOR_SELF_DESCRIBED_TAG = 55799

SOURCE_DATA_EPOCH = 1580601600


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate patch files for Unified Linux Wine Game Launcher compatibility tools",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()

    parser.add_argument("--source", required=True, help="path to source directory")
    parser.add_argument("--target", required=True, help="path to target directory")
    parser.add_argument(
        "--ssh-public-key", required=True, help="path to ed25519 SSH public key"
    )
    parser.add_argument(
        "--ssh-private-key", required=True, help="path to ed25519 SSH private key"
    )
    parser.add_argument(
        "--output", "-o", nargs="?", help="write the result to the file at path OUTPUT"
    )
    group.add_argument(
        "--left",
        action="store_true",
        help="list files exclusively in SOURCE",
    )
    group.add_argument(
        "--right",
        action="store_true",
        help="list files exclusively in TARGET",
    )
    group.add_argument(
        "--diff",
        action="store_true",
        help="list files that differ between SOURCE and TARGET",
    )
    if not sys.argv[1:]:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()


def build_patch(
    src: Path,
    target: Path,
    private_key: str,
    public_key: str,
) -> CustomDataItemContainer:
    with ThreadPoolExecutor() as thread_pool:
        builders: list[Builder] = []
        data_items: list[CustomDataItem] = []

        builders.append(Builder(str(src), str(target), thread_pool))

        for left, right in get_versioned_subdirectories(str(src), str(target)):
            builders.append(Builder(str(left), str(right), thread_pool))

        for builder in builders:
            builder.build()
            item: CustomDataItem = {
                "manifest": builder.get_manifest_section(),
                "update": builder.get_difference_section(),
                "delete": builder.get_delete_section(),
                "add": builder.get_create_section(),
                "source": builder.get_src_base(),
                "target": builder.get_target_base(),
            }
            data_items.append(item)

        try:
            with Path(private_key).resolve().open("rb") as fp:
                sig: str = ssh_sign(fp.read(), dumps(data_items, canonical=True))
        except FileNotFoundError as e:
            err = f"Failed opening SSH private key: {private_key}"
            raise FileNotFoundError(err) from e

        item_container: CustomDataItemContainer = {
            "contents": data_items,
            "signature": (sig.encode(encoding="utf-8"), b""),
            "public_key": (Path(public_key).resolve().read_text(encoding="utf-8"), b""),
        }

        return item_container


def verify_patch(fp: BufferedRandom) -> None:
    fp.seek(0)
    cbor: CustomDataItemContainer = load(fp)
    message = dumps(cbor.get("contents"), canonical=True)

    # Verify the message
    try:
        ssh_verify(cbor["public_key"][0], message, cbor["signature"][0])
    except OSError as e:
        err = "Digital signature verification failed"
        raise ValueError(err) from e

    print(f"Message (SHA512): {sha512(message).hexdigest()}", file=sys.stderr)


def create_patch(
    src: Path,
    target: Path,
    key_pair: tuple[str, str],
    file: str,
) -> int:
    ret = 0
    ssh_private_key_path, ssh_public_key_path = key_pair
    ssh_private_key: str
    ssh_public_key: str

    # SSH keys
    try:
        ssh_private_key = str(Path(ssh_private_key_path).resolve(strict=True))
    except FileNotFoundError as e:
        err = f"Failed opening SSH private key: {ssh_private_key_path}"
        raise FileNotFoundError(err) from e

    try:
        ssh_public_key = str(Path(ssh_public_key_path).resolve(strict=True))
    except FileNotFoundError as e:
        err = f"Failed opening SSH public key: {ssh_public_key_path}"
        raise FileNotFoundError(err) from e

    # Patch
    patch = build_patch(src, target, ssh_private_key, ssh_public_key)

    # File
    # By default, write CBOR byte string to stdout
    # This enables the following usage from the terminal:
    # $ umu-mkpatch --source foo --target bar ... > baz.cbor
    if not file:
        message = dumps(CBORTag(CBOR_SELF_DESCRIBED_TAG, patch), canonical=True)
        # Before writing to stdout, verify the message
        with open(os.memfd_create(src.name, os.MFD_CLOEXEC), mode="rb+") as fp:
            fp.write(message)
            verify_patch(fp)
        sys.stdout.buffer.write(message)
        return ret

    with open(file, "wb+") as fp:
        dump(CBORTag(CBOR_SELF_DESCRIBED_TAG, patch), fp, canonical=True)
        fp.seek(0)
        os.utime(fp.fileno(), times=(SOURCE_DATA_EPOCH, SOURCE_DATA_EPOCH))
        print(f"Created CBOR file '{file}'", file=sys.stderr)
        # Verify message with the user's public key and generated digital signature
        verify_patch(fp)

    print(
        f"SSH public key (SHA512): {sha512(Path(ssh_public_key).read_bytes()).hexdigest()}",
        file=sys.stderr,
    )

    return ret


def main() -> int:
    ret = 0
    args = parse_args()

    # Build files
    src = Path(getattr(args, "source")).resolve(strict=True)
    target = Path(getattr(args, "target")).resolve(strict=True)

    # Patch file
    output = getattr(args, "output") or ""

    # SSH keys used for creating signature and signing patch data
    ssh_private_key_path = getattr(args, "ssh_private_key") or ""
    ssh_public_key_path = getattr(args, "ssh_public_key") or ""

    if output:
        output = str(Path(output).resolve())

    # Handle user CLI arguments
    # Files in the 'left' need to be removed in the 'right'
    if getattr(args, "left"):
        for dirs in compare_directories(str(src), str(target)):
            if dirs.left_only:
                print(f"Files only in '{dirs.left}': {dirs.left_only}", file=sys.stderr)
        return ret

    # Files in the 'right' need to be created and inserted
    if getattr(args, "right"):
        for dirs in compare_directories(str(src), str(target)):
            if dirs.right_only:
                print(
                    f"Files only in '{dirs.right}': {dirs.right_only}", file=sys.stderr
                )
        return ret

    # Files that differ will have patch data created
    if getattr(args, "diff"):
        for dirs in compare_directories(str(src), str(target)):
            if dirs.diff_files:
                print(f"Comparing '{dirs.left}' and '{dirs.right}'", file=sys.stderr)
                print(f"Differing files: {dirs.diff_files}", file=sys.stderr)
        return ret

    return create_patch(
        src, target, (ssh_private_key_path, ssh_public_key_path), output
    )


if __name__ == "__main__":
    sys.exit(main())
