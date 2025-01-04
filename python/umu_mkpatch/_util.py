import filecmp
from collections import deque
from collections.abc import Generator
from difflib import SequenceMatcher
from hashlib import file_digest
from pathlib import Path
from typing import Any

MATCHER_RATIO = 0.70


def compare_directories(
    src: str, target: str
) -> Generator[filecmp.dircmp[str], Any, None]:
    """Recursively compares the contents of two directories."""
    stack = deque([(src, target)])

    while stack:
        current_dir1, current_dir2 = stack.pop()
        dcmp = filecmp.dircmp(current_dir1, current_dir2)
        yield dcmp
        # Add subdirectories to the stack for further comparison
        for subdir in dcmp.common_dirs:
            stack.append((f"{current_dir1}/{subdir}", f"{current_dir2}/{subdir}"))


def get_versioned_subdirectories(src: str, target: str) -> list[tuple[str, str]]:
    subdirectories = []

    for dirs in compare_directories(src, target):
        for file in dirs.right_only:
            name = Path(f"{dirs.right}/{file}")

            if not name.is_dir() and not name.is_symlink():
                continue

            left_dirs = (
                path
                for path in Path(dirs.left).glob("*")
                if path.is_dir() and not path.is_symlink()
            )

            # Find a matching subdirectory
            for lefts in left_dirs:
                fname_right = name.name
                fname_left = lefts.name
                matcher = SequenceMatcher(None, fname_right, fname_left)

                if matcher.quick_ratio() < MATCHER_RATIO:
                    continue

                subdirectories.append((str(lefts), str(name)))

    return subdirectories


def get_file_digest(path: Path, secure_hash: str) -> bytes:
    with path.open("rb") as fp:
        return file_digest(fp, secure_hash).digest()


def get_rpath_from_base(path: Path, base: str) -> Path:
    base_idx = 0

    for idx, segment in enumerate(path.parts):
        if segment == base:
            base_idx = idx
            break

    return Path(*path.parts[base_idx + 1 :])
