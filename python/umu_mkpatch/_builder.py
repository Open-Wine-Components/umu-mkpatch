import filecmp
import mmap
import sys
from collections import deque
from collections.abc import Generator
from concurrent.futures.thread import ThreadPoolExecutor
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from _types import FileType, Item, Manifest
from pyzstd import CParameter, ZstdDict, compress
from xxhash import xxh3_64_intdigest

# Similarity ratio of two file names.
# If two files are below the similarity ratio, then they're assumed to be
# different. Without computing similarity ratios, our patcher would fail to
# update the subdirectory, and delete it instead
MATCHER_RATIO = 0.70

ZSTD_LOG_WINDOW_MIN = 10

ZSTD_LOG_WINDOW_MAX = 31


class Builder:
    def __init__(
        self,
        src: str,
        target: str,
        thread_pool: ThreadPoolExecutor,
    ) -> None:
        self._thread_pool = thread_pool
        self._src = src
        self._target = target
        self._difference_section: list[Item] = []
        self._delete_section: list[Item] = []
        self._create_section: list[Item] = []
        self._manifest_section: list[Manifest] = []

    def get_src_base(self) -> str:
        return Path(self._src).name

    def get_target_base(self) -> str:
        return Path(self._target).name

    def get_thread_pool(self) -> ThreadPoolExecutor:
        return self._thread_pool

    def set_thread_pool(self, obj: ThreadPoolExecutor) -> None:
        self._thread_pool = obj

    def get_src(self) -> str:
        return self._src

    def set_src(self, obj: str) -> None:
        self._src = obj

    def get_target(self) -> str:
        return self._target

    def set_target(self, obj: str) -> None:
        self._target = obj

    def get_manifest_section(self) -> list[Manifest]:
        return self._manifest_section

    def get_create_section(self) -> list[Item]:
        return self._create_section

    def get_delete_section(self) -> list[Item]:
        return self._delete_section

    def get_difference_section(self) -> list[Item]:
        return self._difference_section

    def build(self) -> None:
        futures = [
            self._thread_pool.submit(self._build_manifest_section),
            self._thread_pool.submit(self._build_create_section),
            self._thread_pool.submit(self._build_delete_section),
            self._thread_pool.submit(self._build_difference_section),
        ]
        for future in futures:
            future.result()

    def _build_manifest_section(self) -> list[Manifest]:
        src = Path(self._src)

        for path in (
            file for file in src.rglob("*") if file.is_file() and not file.is_symlink()
        ):
            stats = path.stat()
            rpath = self._get_rpath_from_base(path, src.name)
            xxhash = xxh3_64_intdigest(path.read_bytes())
            self._manifest_section.append(
                {
                    "xxhash": xxhash,
                    "name": str(rpath),
                    "mode": stats.st_mode,
                    "size": stats.st_size,
                    "time": stats.st_mtime,
                }
            )

        return self._manifest_section

    def _build_difference_section(self) -> list[Item]:
        # Files that differ need a delta
        proton_build_target = Path(self._target)
        proton_base = proton_build_target.name
        futures = []

        for dirs in self._compare_directories():
            for file in dirs.diff_files:
                futures.append(
                    self._thread_pool.submit(
                        self._create_content, dirs, file, proton_base
                    )
                )

        for future in futures:
            future.result()

        return self._difference_section

    def _build_delete_section(self) -> list[Item]:
        proton_build_src = Path(self._src)
        proton_base = proton_build_src.name
        futures = []

        # Files in 'left' need to be deleted
        for dirs in self._compare_directories():
            for file in dirs.left_only:
                futures.append(
                    self._thread_pool.submit(
                        self._create_deleted_content, dirs, file, proton_base
                    )
                )

        for future in futures:
            future.result()

        return self._delete_section

    def _build_create_section(self) -> list[Item]:
        proton_build_target = Path(self._target)
        proton_base = proton_build_target.name
        futures = []

        # Files in 'right' need to be created
        for dirs in self._compare_directories():
            for file in dirs.right_only:
                futures.append(
                    self._thread_pool.submit(
                        self._create_new_content, dirs, file, proton_base
                    )
                )

        for future in futures:
            future.result()

        return self._create_section

    def _compare_directories(self) -> Generator[filecmp.dircmp[str], Any, None]:
        """Recursively compares the contents of two directories."""
        stack = deque([(self._src, self._target)])
        while stack:
            current_dir1, current_dir2 = stack.pop()
            dcmp = filecmp.dircmp(current_dir1, current_dir2)
            yield dcmp
            # Add subdirectories to the stack for further comparison
            for subdir in dcmp.common_dirs:
                stack.append((f"{current_dir1}/{subdir}", f"{current_dir2}/{subdir}"))

    def _get_file_type(self, path: Path) -> FileType:
        if path.is_block_device():
            return FileType.Block
        if path.is_char_device():
            return FileType.Char
        if path.is_dir():
            return FileType.Dir
        if path.is_fifo():
            return FileType.Fifo
        if path.is_symlink():
            return FileType.Link
        if path.is_socket():
            return FileType.Socket

        return FileType.File

    def _create_content(
        self,
        dirs: filecmp.dircmp,
        file: str,
        base: str,
    ) -> list[Item]:
        name = Path(f"{dirs.right}/{file}")
        ftype = self._get_file_type(name)

        # Only create patches for real files
        if ftype not in {FileType.File, FileType.Link}:
            return self._difference_section

        if ftype == FileType.File:
            with (
                open(f"{dirs.right}/{file}", "rb") as right,
                open(f"{dirs.left}/{file}", "rb") as left,
                mmap.mmap(
                    right.fileno(), length=0, access=mmap.ACCESS_READ
                ) as right_map,
                mmap.mmap(left.fileno(), length=0, access=mmap.ACCESS_READ) as left_map,
            ):
                base_rpath = self._get_rpath_from_base(name, base)
                zst_dict = ZstdDict(left_map, is_raw=True)
                window_log = max(len(left_map), len(right_map)).bit_length()

                # When small, replace the file
                if window_log < ZSTD_LOG_WINDOW_MIN:
                    self._difference_section.append(
                        {
                            "name": str(base_rpath),
                            "type": ftype,
                            "xxhash": xxh3_64_intdigest(right_map),
                            "data": Path(f"{dirs.right}/{file}").read_bytes(),
                            "mode": name.stat(follow_symlinks=False).st_mode,
                            "time": name.stat(follow_symlinks=False).st_mtime,
                            "size": name.stat(follow_symlinks=False).st_size,
                        }
                    )
                    return self._difference_section

                # If there's a 2GB file, skip. That's wrong and should
                # be reported upstream
                if window_log > ZSTD_LOG_WINDOW_MAX:
                    print(f"File '{name}' > 2GB, skipping", file=sys.stderr)
                    return self._difference_section

                zst_opts = {
                    CParameter.windowLog: window_log,
                    CParameter.enableLongDistanceMatching: 1,
                }

                patch = compress(
                    right_map,
                    level_or_option=zst_opts,
                    zstd_dict=zst_dict.as_prefix,
                )

                self._difference_section.append(
                    {
                        "name": str(base_rpath),
                        "type": ftype,
                        "xxhash": xxh3_64_intdigest(right_map),
                        "data": patch,
                        "mode": name.stat(follow_symlinks=False).st_mode,
                        "time": name.stat(follow_symlinks=False).st_mtime,
                        "size": name.stat(follow_symlinks=False).st_size,
                    }
                )

        if ftype == FileType.Link:
            base_rpath = self._get_rpath_from_base(name, base)
            self._difference_section.append(
                {
                    "name": str(base_rpath),
                    "type": ftype,
                    "xxhash": 0,
                    "data": bytes(name.readlink()),
                    "mode": name.stat(follow_symlinks=False).st_mode,
                    "time": name.stat(follow_symlinks=False).st_mtime,
                    "size": 0,
                }
            )

        return self._difference_section

    def _get_rpath_from_base(self, path: Path, base: str) -> Path:
        base_idx = 0

        for idx, segment in enumerate(path.parts):
            if segment == base:
                base_idx = idx
                break

        return Path(*path.parts[base_idx + 1 :])

    def _create_new_content(
        self,
        dirs: filecmp.dircmp,
        file: str,
        base: str,
    ) -> list[Item]:
        name = Path(f"{dirs.right}/{file}")
        ftype = self._get_file_type(name)

        if ftype not in (FileType.Dir, FileType.File, FileType.Link):
            print(f"File is type '{ftype}', will not add to ADD section...")
            return self._create_section

        # Omit cksum, data and size for dirs
        if ftype == FileType.Dir:
            base_rpath = self._get_rpath_from_base(name, base)

            # Handle the versioned subdirectory case
            left_dirs = (
                path
                for path in Path(dirs.left).glob("*")
                if path.is_dir() and not path.is_symlink()
            )

            # Find a matching subdirectory
            for lefts in left_dirs:
                fname_right = lefts.name
                fname_left = name.name
                matcher = SequenceMatcher(None, fname_right, fname_left)

                if matcher.quick_ratio() < MATCHER_RATIO:
                    continue

                # If a match was found, don't mark directory for deletion.
                # A comparison will need to be performed separately for it
                return self._create_section

            self._create_section.append(
                {
                    "name": str(base_rpath),
                    "type": ftype,
                    "xxhash": 0,
                    "data": b"",
                    "mode": name.stat(follow_symlinks=False).st_mode,
                    "time": name.stat(follow_symlinks=False).st_mtime,
                    "size": 0,
                }
            )

            # If the directory has contents, include them
            for f in name.rglob("*"):
                base_rpath = self._get_rpath_from_base(f, base)
                ftype = self._get_file_type(f)

                # Omit cksum, data and size for links
                if ftype == FileType.Link:
                    self._create_section.append(
                        {
                            "name": str(base_rpath),
                            "type": ftype,
                            "xxhash": 0,
                            "data": bytes(f.readlink()),
                            "mode": f.stat(follow_symlinks=False).st_mode,
                            "time": f.stat(follow_symlinks=False).st_mtime,
                            "size": 0,
                        }
                    )
                    continue

                if ftype == FileType.Dir:
                    self._create_section.append(
                        {
                            "name": str(base_rpath),
                            "type": ftype,
                            "xxhash": 0,
                            "data": b"",
                            "mode": f.stat(follow_symlinks=False).st_mode,
                            "time": f.stat(follow_symlinks=False).st_mtime,
                            "size": 0,
                        }
                    )
                    continue

                if ftype == FileType.File:
                    self._create_section.append(
                        {
                            "name": str(base_rpath),
                            "type": ftype,
                            "xxhash": xxh3_64_intdigest(f.read_bytes()),
                            "data": self._get_compressed_content_data(str(f)),
                            "mode": f.stat(follow_symlinks=False).st_mode,
                            "time": f.stat(follow_symlinks=False).st_mtime,
                            "size": f.stat(follow_symlinks=False).st_size,
                        }
                    )

            return self._create_section

        # Omit cksum, data and size for links
        if ftype == FileType.Link:
            base_rpath = self._get_rpath_from_base(name, base)
            self._create_section.append(
                {
                    "name": str(base_rpath),
                    "type": ftype,
                    "xxhash": 0,
                    "data": bytes(name.readlink()),
                    "mode": name.stat(follow_symlinks=False).st_mode,
                    "time": name.stat(follow_symlinks=False).st_mtime,
                    "size": 0,
                }
            )
            return self._create_section

        base_rpath = self._get_rpath_from_base(name, base)
        self._create_section.append(
            {
                "name": str(base_rpath),
                "type": ftype,
                "xxhash": xxh3_64_intdigest(Path(f"{dirs.right}/{file}").read_bytes()),
                "data": self._get_compressed_content_data(f"{dirs.right}/{file}"),
                "mode": name.stat(follow_symlinks=False).st_mode,
                "time": name.stat(follow_symlinks=False).st_mtime,
                "size": name.stat(follow_symlinks=False).st_size,
            }
        )

        return self._create_section

    def _get_compressed_content_data(self, path: str) -> bytes:
        with open(path, "rb") as fp:
            return compress(fp.read(), level_or_option=3)

    def _create_deleted_content(
        self,
        dirs: filecmp.dircmp,
        file: str,
        base: str,
    ) -> list[Item]:
        name = Path(f"{dirs.left}/{file}")
        ftype = self._get_file_type(name)

        if ftype not in (FileType.File, FileType.Dir, FileType.Link):
            print(f"File is type f'{ftype}', will not add to DELETE section...")
            return self._delete_section

        # Zero the checksum
        if ftype == FileType.Link:
            base_rpath = self._get_rpath_from_base(name, base)
            self._delete_section.append(
                {
                    "name": str(base_rpath),
                    "type": ftype,
                    "xxhash": 0,
                    "data": bytes(name.readlink()),
                    "mode": name.stat(follow_symlinks=False).st_size,
                    "time": name.stat(follow_symlinks=False).st_mtime,
                    "size": 0,
                }
            )
            return self._delete_section

        # Zero the checksum and data fields for directories
        if ftype == FileType.Dir:
            base_rpath = self._get_rpath_from_base(name, base)

            # Handle the versioned subdirectory case
            right_dirs = (
                path
                for path in Path(dirs.right).glob("*")
                if path.is_dir() and not path.is_symlink()
            )

            # Find a matching subdirectory
            for rights in right_dirs:
                fname_right = rights.name
                fname_left = name.name
                matcher = SequenceMatcher(None, fname_right, fname_left)

                if matcher.quick_ratio() < MATCHER_RATIO:
                    continue

                # If a match was found, don't mark directory for deletion.
                # A comparison will need to be performed separately for it
                return self._delete_section

            self._delete_section.append(
                {
                    "name": str(base_rpath),
                    "type": ftype,
                    "xxhash": 0,
                    "data": b"",
                    "mode": name.stat(follow_symlinks=False).st_size,
                    "time": name.stat(follow_symlinks=False).st_mtime,
                    "size": 0,
                }
            )
            return self._delete_section

        # Zero the data field while preserving cksum/size as we don't care about
        # the data when deleting
        base_rpath = self._get_rpath_from_base(name, base)
        self._delete_section.append(
            {
                "name": str(base_rpath),
                "type": ftype,
                "xxhash": xxh3_64_intdigest(Path(f"{dirs.left}/{file}").read_bytes()),
                "data": b"",
                "mode": name.stat(follow_symlinks=False).st_size,
                "time": name.stat(follow_symlinks=False).st_mtime,
                "size": name.stat(follow_symlinks=False).st_size,
            }
        )

        return self._delete_section
