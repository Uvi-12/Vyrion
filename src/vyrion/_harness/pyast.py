"""Shared Python-AST discovery for agent frameworks.

Finds approval points, action points, and import-based detection from real source
using the standard library ast module. Framework harnesses configure which call
names and keyword arguments mark an approval, and which decorators or calls mark a
protected action.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class AstHit:
    node: ast.AST
    path: str
    text: str
    construct: str


class ApprovalScanner(ast.NodeVisitor):
    def __init__(self, path: str, text: str,
                 call_names: set[str], kw_flags: set[str],
                 decorator_names: set[str], action_call_names: set[str],
                 approval_def_names: set[str] | None = None,
                 action_def_names: set[str] | None = None):
        self.path, self.text = path, text
        self.call_names = call_names
        self.kw_flags = kw_flags
        self.decorator_names = decorator_names
        self.action_call_names = action_call_names
        self.approval_def_names = approval_def_names or set()
        self.action_def_names = action_def_names or set()
        self.approvals: list[AstHit] = []
        self.actions: list[AstHit] = []

    @staticmethod
    def _callee(node: ast.Call) -> str:
        f = node.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            return f.attr
        return ""

    def visit_Call(self, node: ast.Call):
        name = self._callee(node)
        if name in self.call_names:
            self.approvals.append(AstHit(node, self.path, self.text, f"{name}() call"))
        # keyword flag form, e.g. needs_approval=True / requires_confirmation=True
        for kw in node.keywords:
            if kw.arg in self.kw_flags:
                truthy = not (isinstance(kw.value, ast.Constant) and kw.value.value in (False, None))
                if truthy:
                    self.approvals.append(
                        AstHit(node, self.path, self.text, f"{kw.arg}= approval kwarg"))
        if name in self.action_call_names:
            self.actions.append(AstHit(node, self.path, self.text, f"{name}() action call"))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if node.name in self.approval_def_names:
            self.approvals.append(AstHit(node, self.path, self.text, f"def {node.name}() approval step"))
        if node.name in self.action_def_names:
            self.actions.append(AstHit(node, self.path, self.text, f"def {node.name}() protected action"))
        for dec in node.decorator_list:
            dname = self._dec_name(dec)
            if dname in self.decorator_names:
                self.actions.append(
                    AstHit(node, self.path, self.text, f"@{dname} protected action"))
            # decorator with approval kwarg, e.g. @tool(needs_approval=True)
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg in self.kw_flags:
                        self.approvals.append(
                            AstHit(dec, self.path, self.text, f"{kw.arg}= on @{self._dec_name(dec)}"))
        self.generic_visit(node)

    @staticmethod
    def _dec_name(dec: ast.AST) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        if isinstance(dec, ast.Attribute):
            return dec.attr
        if isinstance(dec, ast.Call):
            return ApprovalScanner._dec_name(dec.func)
        return ""


def scan_python(path: str, text: str, *, call_names, kw_flags, decorator_names,
                action_call_names, approval_def_names=None,
                action_def_names=None) -> ApprovalScanner:
    scanner = ApprovalScanner(path, text, set(call_names), set(kw_flags),
                              set(decorator_names), set(action_call_names),
                              set(approval_def_names or []),
                              set(action_def_names or []))
    try:
        scanner.visit(ast.parse(text))
    except SyntaxError:
        pass
    return scanner


def imports_any(text: str, needles: set[str]) -> bool:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return any(n in text for n in needles)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if any(a.name.startswith(n) for n in needles):
                    return True
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if any(mod.startswith(n) for n in needles):
                return True
    return False
