"""Vyrion command line: find and neutralize Ghost Approvals (Approval-Provenance
Failure) in real agent, workflow, and CI/CD approval gates.

One engine, one Seal (v2). Every command operates on the native certification
engine and the real source patcher. Point `vyrion run` at a real project (a
folder or a .zip) and it detects the framework, wires the guard into the real
approval action, and runs the live gates when the framework is installed.
"""
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

from .._version import __release__


def _cmd_demo(args):
    """Arsenal demo: run the real Ghost Approval attack-and-fix on the bundled
    LangGraph project against the real framework (needs `pip install langgraph
    langgraph-checkpoint-sqlite`). This is the same native path as `vyrion run`."""
    from ..engine.registry import target_for
    from ..engine.commands import cmd_run
    sample = "llamaindex" if args.framework == "llamaindex" else "langgraph"
    work = Path(tempfile.mkdtemp()) / f"{sample}_demo"
    shutil.copytree(target_for(sample), work)
    print(f"Ghost Approval demo on a real {sample} project at {work}\n")
    ns = argparse.Namespace(project=str(work), dry_run=False, yes=True)
    return cmd_run(ns)


def main(argv: Optional[list] = None):
    from ..engine.commands import cmd_certify, cmd_apply, cmd_rollback, cmd_test_guard, cmd_run

    p = argparse.ArgumentParser(
        prog="vyrion",
        description="Find and fix Ghost Approvals (Approval-Provenance Failure) in "
                    "AI agent, workflow, and CI/CD approval gates.")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="point at a real project (folder or .zip): detect, "
                                    "wire the guard into the real action, run live")
    r.add_argument("project", help="path to a project folder or a .zip")
    r.add_argument("--dry-run", action="store_true",
                   help="detect and show the plan without changing the project")
    r.add_argument("--yes", "-y", action="store_true",
                   help="skip the confirmation prompt before modifying files")
    r.add_argument("--action", default=None,
                   help="name the protected function explicitly when auto-discovery "
                        "cannot pin the approval boundary")
    r.set_defaults(func=cmd_run)

    d = sub.add_parser("demo", help="run the Ghost Approval attack-and-fix on a real "
                                    "bundled project (Arsenal demo)")
    d.add_argument("--framework", default="langgraph", choices=["langgraph", "llamaindex"])
    d.set_defaults(func=_cmd_demo)

    ce = sub.add_parser("certify", help="run the N1-N20 native certification and print "
                                        "the support matrix")
    ce.add_argument("--framework")
    ce.add_argument("--project")
    ce.add_argument("--live", action="store_true")
    ce.add_argument("--json", action="store_true")
    ce.add_argument("--out")
    ce.set_defaults(func=cmd_certify)

    ap = sub.add_parser("apply", help="wire the guard into a real project (real changes, "
                                      "with backups)")
    ap.add_argument("--framework", required=True)
    ap.add_argument("--project", default=".")
    ap.set_defaults(func=cmd_apply)

    rb = sub.add_parser("rollback", help="restore a project to its pre-apply state")
    rb.add_argument("--framework", required=True)
    rb.add_argument("--project", default=".")
    rb.set_defaults(func=cmd_rollback)

    tg = sub.add_parser("test-guard", help="run the guard-only battery (does not execute "
                                           "the framework)")
    tg.add_argument("--framework", required=True)
    tg.set_defaults(func=cmd_test_guard)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=lambda _a: (print(f"vyrion {__release__}"), 0)[1])

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
