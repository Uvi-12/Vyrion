"""File discovery must be deterministic and OS-independent.

Every adapter resolves the protected action by scanning the project's source
files. If that scan is ordered by the filesystem, the same repository can
resolve a different approval point on a different machine. These tests assert
the scan is sorted and stable.
"""
import os

from vyrion.engine.adapters import LangGraphNativeAdapter


def _make_tree(root):
    # Create files out of alphabetical order on disk.
    for name in ["zeta.py", "alpha.py", "middle.py"]:
        (root / name).write_text("x = 1\n")
    sub = root / "pkg"
    sub.mkdir()
    for name in ["gamma.py", "beta.py"]:
        (sub / name).write_text("y = 2\n")


def test_py_files_is_sorted_and_stable(tmp_path):
    _make_tree(tmp_path)
    a = LangGraphNativeAdapter()
    first = list(a._py_files(str(tmp_path)))
    assert first == sorted(first), "file discovery is not sorted"
    # stable across repeated calls
    for _ in range(3):
        assert list(a._py_files(str(tmp_path))) == first


def test_py_files_prunes_noise_dirs(tmp_path):
    _make_tree(tmp_path)
    for noise in [".venv", "__pycache__", "node_modules", ".git"]:
        d = tmp_path / noise
        d.mkdir()
        (d / "junk.py").write_text("z = 3\n")
    a = LangGraphNativeAdapter()
    found = list(a._py_files(str(tmp_path)))
    assert not any(os.sep + noise + os.sep in p
                   for p in found
                   for noise in (".venv", "__pycache__", "node_modules", ".git")), found
