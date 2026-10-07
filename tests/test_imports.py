"""Every module imports cleanly, with only the declared dependencies installed.

This exists because of a real bug. `engine/humanize.py` imported `dotenv` at module
scope while `python-dotenv` was not a declared dependency, so importing that module
raised ModuleNotFoundError. Nothing caught it, because nothing imported the module
and its coverage was zero. Two defects hid each other.

Importing every module under the gated directories catches both: an undeclared
dependency fails here, and a module no entry point reaches is at least proven to
load.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

PACKAGES = ("engine", "store")


def _module_names() -> list[str]:
    names: list[str] = []
    for package in PACKAGES:
        root = importlib.import_module(package)
        names.append(package)
        for info in pkgutil.walk_packages(root.__path__, prefix=f"{package}."):
            names.append(info.name)
    return sorted(names)


@pytest.mark.parametrize("name", _module_names())
def test_module_imports(name: str) -> None:
    # A failure here is almost always a dependency used in the code but missing
    # from pyproject.toml and from the PEP 723 header in scripts/.
    importlib.import_module(name)


def test_every_script_dependency_is_also_a_project_dependency() -> None:
    """The two dependency lists must agree.

    `scripts/*.py` carry a PEP 723 header so a user needs only `uv`. `pyproject`
    carries the same list for development. A dependency added to one and not the
    other breaks the path that uses the other list, and the dev path is the one
    that usually still passes, so the break ships.
    """
    import pathlib
    import re
    import tomllib

    project = tomllib.loads(pathlib.Path("pyproject.toml").read_text())
    declared = {
        re.split(r"[><=!\[]", d)[0].strip().lower().replace("_", "-")
        for d in project["project"]["dependencies"]
    }
    # openai is an optional extra, so a script may name it without it being a
    # hard requirement.
    declared |= {"openai"}

    for script in sorted(pathlib.Path("scripts").glob("*.py")):
        text = script.read_text()
        block = re.search(r"# /// script\n(.*?)# ///", text, re.S)
        assert block, f"{script} has no PEP 723 header, so `uv run` cannot resolve it"
        # Only the dependencies list. The header also holds requires-python, whose
        # quoted value would otherwise be read as a package name.
        deps = re.search(r"dependencies = \[(.*?)\]", block.group(1), re.S)
        assert deps, f"{script} has a PEP 723 header with no dependencies list"
        names = {
            re.split(r"[><=!\[]", m)[0].strip().lower().replace("_", "-")
            for m in re.findall(r'"([^"]+)"', deps.group(1))
        }
        names.discard("")
        extra = names - declared
        assert not extra, (
            f"{script.name} declares {sorted(extra)}, which pyproject.toml does not. "
            f"Add them there too, or `just check` passes while `uv run` fails."
        )
