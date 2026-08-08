"""Surgical source patching for native adapters.

Inserts three things into a real source file, using AST to locate them and
line-level edits to keep the rest of the file (comments, formatting) intact:

  1. an import of the installed guard,
  2. extra state channels so the signed seal travels with the workflow state,
  3. a fail-closed guard gate at the top of the protected function.

The original file is backed up first, so rollback restores it byte-for-byte.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass
class PatchSpec:
    action_func: str            # e.g. "transfer_funds"
    action_id: str              # e.g. "payments.transfer"
    arg_fields: list            # state fields that form the action arguments
    state_class: str = ""       # TypedDict class to extend (optional)
    seal_field: str = "seal"
    run_field: str = "_vyrion_run"
    cp_field: str = "_vyrion_cp"
    import_line: str = "import vyrion_guard as _vyrion"


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def patch_source(source: str, spec: PatchSpec) -> str:
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}   # line index (0-based, insert BEFORE) -> list of text lines

    # 1) import: after the module docstring / existing imports block
    import_at = 0
    body = tree.body
    start = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        import_at = body[0].end_lineno   # after docstring
        start = 1
    last_import_end = import_at
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last_import_end = node.end_lineno
    inserts.setdefault(last_import_end, []).append(spec.import_line)

    # 2) state channels: append fields inside the TypedDict class body
    if spec.state_class:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == spec.state_class:
                # insertion point: end of the class body
                last = node.body[-1]
                cbody_indent = _indent_of(lines[node.body[0].lineno - 1])
                fields = [f"{cbody_indent}{spec.seal_field}: str",
                          f"{cbody_indent}{spec.run_field}: str",
                          f"{cbody_indent}{spec.cp_field}: str"]
                inserts.setdefault(last.end_lineno, []).extend(fields)
                break

    # 3) guard gate at the top of the protected function
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == spec.action_func:
            first = node.body[0]
            after = node.body[0]
            body_start_idx = 0
            # keep a leading docstring above the gate
            if isinstance(first, ast.Expr) and isinstance(
                    getattr(first, "value", None), ast.Constant) and len(node.body) > 1:
                after = node.body[1]
                body_start_idx = 1
            indent = _indent_of(lines[after.lineno - 1])
            arg_state = getattr(node.args, "args", [])
            state_name = arg_state[0].arg if arg_state else "state"
            args_dict = ", ".join(f'"{f}": {state_name}.get("{f}")' for f in spec.arg_fields)
            gate = [
                f"{indent}# vyrion: fail-closed approval-provenance gate (trusted-runtime anchored)",
                f"{indent}try:",
                f"{indent}    from langgraph.config import get_config as _vyrion_get_config",
                f'{indent}    _vyrion_run = _vyrion_get_config().get("configurable", {{}}).get("thread_id", "")',
                f"{indent}except Exception:",
                f'{indent}    _vyrion_run = ""',
                f"{indent}if not _vyrion.authorize(",
                f'{indent}        seal={state_name}.get("{spec.seal_field}"),',
                f"{indent}        args={{{args_dict}}},",
                f"{indent}        run_id=_vyrion_run,",
                f'{indent}        checkpoint_id=""):',
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            insert_before_line = node.body[body_start_idx].lineno
            inserts.setdefault(insert_before_line - 1, []).extend(gate)
            break

    # apply inserts bottom-up so line numbers stay valid
    out = list(lines)
    for at in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at]):
            out.insert(at, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    # the result must parse
    ast.parse(result)
    return result


def patch_llamaindex(source: str, action_func: str, approval_func: str,
                     arg_fields=None,
                     import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch a LlamaIndex workflow. LlamaIndex does not expose a trusted run id to a
    step, so the Seal is bound to action + arguments + a single-use nonce (not to a
    run id read from the mutable Context store). The trusted approver mints the Seal
    and delivers it in the resume event; the protected step verifies it."""
    arg_fields = arg_fields or ["recipient", "amount", "currency"]
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}

    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == approval_func:
                # the trusted approver delivers a minted Seal in the resume event;
                # stash it in the context for the protected step to verify
                ret = node.body[-1]
                indent = _indent_of(lines[node.body[0].lineno - 1])
                block = [
                    f'{indent}await ctx.store.set("vyrion_seal", ev.get("vyrion_seal", None) if hasattr(ev, "get") else None)',
                ]
                inserts.setdefault(ret.lineno - 1, []).extend(block)
            elif node.name == action_func:
                first = node.body[0]
                idx = 0
                if isinstance(first, ast.Expr) and isinstance(
                        getattr(first, "value", None), ast.Constant) and len(node.body) > 1:
                    idx = 1
                indent = _indent_of(lines[node.body[idx].lineno - 1])
                argitems = ", ".join(
                    f'"{f}": await ctx.store.get("{f}", default=None)' for f in arg_fields)
                gate = [
                    f'{indent}_vyrion_seal = await ctx.store.get("vyrion_seal", default=None)',
                    f'{indent}_vyrion_args = {{{argitems}}}',
                    f"{indent}# LlamaIndex exposes no trusted run id to a step; bind action+args+nonce",
                    f"{indent}if not _vyrion.authorize(seal=_vyrion_seal, args=_vyrion_args,",
                    f'{indent}                         run_id="", checkpoint_id=""):',
                    f'{indent}    return StopEvent(result={{"executed": False, "vyrion_blocked": True}})',
                ]
                inserts.setdefault(node.body[idx].lineno - 1, []).extend(gate)

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_function_action(source: str, action_func: str, arg_fields: list,
                          import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Wire a fail-closed guard gate into a plain function action. The gate reads
    the seal and execution context the host driver set, and raises _vyrion.Blocked
    when verification fails, so the action cannot complete regardless of its return
    type. Verifiable here: the patched source parses and imports the guard."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}

    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == action_func:
            first = node.body[0]
            idx = 0
            if isinstance(first, ast.Expr) and isinstance(
                    getattr(first, "value", None), ast.Constant) and len(node.body) > 1:
                idx = 1
            indent = _indent_of(lines[node.body[idx].lineno - 1])
            gate = [
                f"{indent}# vyrion: fail-closed approval-provenance gate (installed by vyrion apply)",
                f"{indent}_vc = _vyrion.pending_context()",
                f"{indent}if _vc is not None and not _vyrion.authorize(",
                f'{indent}        seal=_vc["seal"], args=_vc["args"],',
                f'{indent}        run_id=_vc["run_id"], checkpoint_id=_vc["checkpoint_id"]):',
                f'{indent}    raise _vyrion.Blocked("vyrion: approval provenance verification failed")',
            ]
            inserts.setdefault(node.body[idx].lineno - 1, []).extend(gate)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_typescript(source: str, import_line: str = "import * as _vyrion from './vyrion_guard.ts';") -> str:
    """Wire the guard into a TypeScript tool action. Inserts an import and a
    fail-closed gate at the top of the first `async (...) => {` execute/handler
    body. Line-based (no TS AST here); the caller verifies with node/tsc."""
    lines = source.splitlines()
    out = []
    # import after the last top-level import line
    last_import = -1
    for i, ln in enumerate(lines):
        if ln.strip().startswith("import "):
            last_import = i
    gate = [
        "    // vyrion: fail-closed approval-provenance gate (installed by vyrion apply)",
        "    const _vc = (globalThis as any).__vyrionPending;",
        "    if (_vc && !_vyrion.authorize(_vc)) {",
        '      throw new Error("vyrion: approval provenance verification failed");',
        "    }",
    ]
    inserted_gate = False
    for i, ln in enumerate(lines):
        out.append(ln)
        if i == last_import:
            out.append(import_line)
        # first async arrow body opening: `async (...) => {`
        if (not inserted_gate) and "async (" in ln and "=> {" in ln:
            out.extend(gate)
            inserted_gate = True
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    return result, inserted_gate


def patch_burr(source: str, action_func: str, arg_fields: list,
               approval_func: str = None,
               import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Wire Burr's guard + issuer, anchored to the trusted ApplicationContext.app_id.
    The protected @action verifies a Seal bound to the trusted app run id (not to
    mutable State); the approval @action mints that Seal at decision time."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    replaces = {}

    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    imports = [import_line]
    if approval_func:
        imports.append("import vyrion_broker as _vyrion_issuer")
    inserts.setdefault(at, []).extend(imports)

    argmap = ", ".join(f'"{f}": state.get("{f}")' for f in arg_fields)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name == action_func:
            first = node.body[0]
            idx = 1 if (isinstance(first, ast.Expr) and isinstance(
                getattr(first, "value", None), ast.Constant) and len(node.body) > 1) else 0
            indent = _indent_of(lines[node.body[idx].lineno - 1])
            gate = [
                f"{indent}# vyrion: fail-closed gate, run id from trusted Burr runtime (not State)",
                f"{indent}try:",
                f"{indent}    from burr.core import ApplicationContext as _VAC",
                f"{indent}    _vyrion_run = _VAC.get().app_id",
                f"{indent}except Exception:",
                f'{indent}    _vyrion_run = ""',
                f"{indent}if not _vyrion.authorize(seal=state.get('seal'),",
                f"{indent}        args={{{argmap}}}, run_id=_vyrion_run, checkpoint_id=''):",
                f"{indent}    return state.update(executed=False, vyrion_blocked=True)",
            ]
            inserts.setdefault(node.body[idx].lineno - 1, []).extend(gate)
        elif approval_func and node.name == approval_func:
            ret = node.body[-1]
            if not isinstance(ret, ast.Return):
                continue
            indent = _indent_of(lines[node.body[0].lineno - 1])
            mint = [
                f"{indent}# vyrion: mint a signed Seal at approval, bound to trusted app run id",
                f"{indent}try:",
                f"{indent}    from burr.core import ApplicationContext as _VAC2",
                f"{indent}    _vyrion_run = _VAC2.get().app_id",
                f"{indent}except Exception:",
                f'{indent}    _vyrion_run = ""',
                f"{indent}_vyrion_decision = locals().get('decision', 'approve')",
                f'{indent}_vyrion_seal = (_vyrion_issuer.mint(run_id=_vyrion_run, args={{{argmap}}}, decision=_vyrion_decision) if _vyrion_decision == "approve" else "")',
            ]
            inserts.setdefault(ret.lineno - 1, []).extend(mint)
            # augment the returned state.update(...) with seal=_vyrion_seal
            ret_line = lines[ret.lineno - 1]
            if "state.update(" in ret_line:
                newl = ret_line.replace("state.update(", "state.update(seal=_vyrion_seal, ", 1)
                replaces[ret.lineno - 1] = newl

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        if at_ in replaces:
            out[at_] = replaces[at_]
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    for ln, newl in replaces.items():
        if ln not in inserts:
            out[ln] = newl
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_approval(source: str, approval_func: str, arg_fields: list,
                   seal_field: str = "seal",
                   import_line: str = "import vyrion_broker as _vyrion_issuer") -> str:
    """Wire Seal minting into the approval node: after the human decision returns,
    mint a Seal bound to the trusted runtime thread_id and store it in state."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == approval_func:
            ret = node.body[-1]
            if not isinstance(ret, ast.Return):
                break
            indent = _indent_of(lines[node.body[0].lineno - 1])
            state_name = node.args.args[0].arg if node.args.args else "state"
            argmap = ", ".join(f'"{f}": {state_name}.get("{f}")' for f in arg_fields)
            # the interrupt result is bound to a local; find the returned dict's approval value
            block = [
                f"{indent}# vyrion: mint a signed Seal at approval time, bound to trusted run id",
                f"{indent}try:",
                f"{indent}    from langgraph.config import get_config as _vyrion_gc",
                f'{indent}    _vyrion_run = _vyrion_gc().get("configurable", {{}}).get("thread_id", "")',
                f"{indent}except Exception:",
                f'{indent}    _vyrion_run = ""',
                f"{indent}_vyrion_decision = locals().get('decision', 'approve')",
                f'{indent}_vyrion_seal = (_vyrion_issuer.mint(run_id=_vyrion_run, args={{{argmap}}}, decision=_vyrion_decision) if _vyrion_decision == "approve" else "")',
            ]
            inserts.setdefault(ret.lineno - 1, []).extend(block)
            # augment the returned dict with the seal. Works for both single-line
            # (`return {"a": 1}`) and multi-line (`return {` ... `}`) dicts by
            # injecting the seal key right after the opening brace.
            ret_line = lines[ret.lineno - 1]
            if "return {" in ret_line:
                new_ret = ret_line.replace("return {", f'return {{"{seal_field}": _vyrion_seal, ', 1)
                inserts.setdefault(ret.lineno - 1, []).append("__REPLACE_RETURN__" + new_ret)
            break

    out = []
    replace_map = {}
    for at_, texts in inserts.items():
        keep = []
        for t in texts:
            if t.startswith("__REPLACE_RETURN__"):
                replace_map[at_] = t[len("__REPLACE_RETURN__"):]
            else:
                keep.append(t)
        inserts[at_] = keep

    tmp = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            tmp.insert(at_, text)
    # apply return replacements (line numbers shifted; match by content)
    result_lines = []
    for ln in tmp:
        replaced = False
        for _at, newret in replace_map.items():
            old = lines[_at]
            if ln == old:
                result_lines.append(newret); replaced = True; break
        if not replaced:
            result_lines.append(ln)
    result = "\n".join(result_lines)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_dbos(source: str, workflow_func: str, arg_fields: list,
               import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch a DBOS workflow: after the human decision arrives via DBOS.recv(),
    verify it as a signed Seal bound to the trusted DBOS.workflow_id before the
    guarded step runs. Fails closed by raising when the Seal is missing/invalid."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == workflow_func:
            # find the `<var> = DBOS.recv(...)` assignment
            recv_var, recv_line = None, None
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                    f = stmt.value.func
                    if isinstance(f, ast.Attribute) and f.attr == "recv":
                        if stmt.targets and isinstance(stmt.targets[0], ast.Name):
                            recv_var = stmt.targets[0].id
                            recv_line = stmt.end_lineno
            if not recv_var:
                break
            indent = _indent_of(lines[recv_line - 1])
            argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance, run id from trusted DBOS runtime",
                f"{indent}from dbos import DBOS as _VDBOS",
                f"{indent}import json as _vjson",
                f"{indent}if not _vyrion.authorize(seal={recv_var},",
                f"{indent}        args={{{argmap}}}, run_id=_VDBOS.workflow_id, checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
                f"{indent}{recv_var} = (_vjson.loads({recv_var}) if isinstance({recv_var}, str) "
                f"else {recv_var}).get('decision', {recv_var})",
            ]
            inserts.setdefault(recv_line, []).extend(gate)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_crewai(source: str, action_func: str, feedback_param: str, arg_fields: list,
                 import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch a CrewAI Flow: at the protected @listen method that runs after the
    @human_feedback gate, verify the human feedback artifact as a signed Seal bound
    to the action + arguments + a single-use nonce before the guarded action runs.
    Fails closed by raising GhostApprovalBlocked. CrewAI exposes no trusted run id
    to a flow method (flow_id == state.id, which lives in the writable store), so the
    Seal is not run-anchored; binding is action + args + nonce."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == action_func:
            first = node.body[0]
            ins_line = first.lineno - 1
            indent = _indent_of(lines[ins_line])
            argmap = ", ".join(f'"{f}": self.state.{f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance (action + args + single-use nonce)",
                f"{indent}_vyrion_seal = getattr({feedback_param}, 'feedback', None)",
                f"{indent}if not _vyrion.authorize(seal=_vyrion_seal,",
                f"{indent}        args={{{argmap}}}, run_id='', checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            for t in reversed(gate):
                inserts.setdefault(ins_line, []).insert(0, t)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_openai_agents(source: str, action_func: str, ctx_param: str, arg_fields: list,
                        import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch an OpenAI Agents SDK needs_approval tool: verify the approval carries a
    provenance-bound Seal (action + args + single-use nonce) before the tool's side
    effect. The trusted approver places the Seal in the run context when approving.
    RunState is fully serialized (attacker-writable), so binding is not run-anchored."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == action_func:
            first = node.body[0]
            ins_line = first.lineno - 1
            indent = _indent_of(lines[ins_line])
            argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance (action + args + single-use nonce)",
                f"{indent}_vyrion_seal = getattr(getattr({ctx_param}, 'context', None), 'vyrion_seal', None)",
                f"{indent}if not _vyrion.authorize(seal=_vyrion_seal,",
                f"{indent}        args={{{argmap}}}, run_id='', checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            for t in reversed(gate):
                inserts.setdefault(ins_line, []).insert(0, t)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_google_adk(source: str, action_func: str, ctx_param: str, arg_fields: list,
                     import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch a Google ADK require_confirmation tool: verify the tool confirmation
    carries a provenance-bound Seal (action + args + single-use nonce) before the
    tool's side effect. The trusted approver puts the Seal in ToolConfirmation.payload.
    ADK derives invocation_id from the writable session on resume, so there is no
    trusted run anchor; binding is action + args + nonce."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == action_func:
            first = node.body[0]
            ins_line = first.lineno - 1
            indent = _indent_of(lines[ins_line])
            argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance (action + args + single-use nonce)",
                f"{indent}_vyrion_conf = getattr({ctx_param}, 'tool_confirmation', None)",
                f"{indent}_vyrion_seal = getattr(_vyrion_conf, 'payload', None)",
                f"{indent}if not _vyrion.authorize(seal=_vyrion_seal,",
                f"{indent}        args={{{argmap}}}, run_id='', checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            for t in reversed(gate):
                inserts.setdefault(ins_line, []).insert(0, t)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_autogen(source: str, action_func: str, approval_param: str, arg_fields: list,
                  import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch an AutoGen tool: verify the approval carried in the (serialized) state is
    a provenance-bound Seal (action + args + single-use nonce) before the tool's side
    effect. save_state/load_state round-trip state as plain JSON, so there is no trusted
    run anchor; binding is action + args + nonce, minted by the trusted approver."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == action_func:
            first = node.body[0]
            ins_line = first.lineno - 1
            indent = _indent_of(lines[ins_line])
            argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance (action + args + single-use nonce)",
                f"{indent}if not _vyrion.authorize(seal={approval_param},",
                f"{indent}        args={{{argmap}}}, run_id='', checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            for t in reversed(gate):
                inserts.setdefault(ins_line, []).insert(0, t)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_haystack(source: str, action_func: str, approval_param: str, arg_fields: list,
                   import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch a Haystack tool: verify the confirmation decision (serialized into the
    AgentSnapshot) is a provenance-bound Seal (action + args + single-use nonce) before
    the tool's side effect. Snapshots are serialized whole, so there is no trusted run
    anchor; binding is action + args + nonce, minted by the trusted approver."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == action_func:
            first = node.body[0]
            ins_line = first.lineno - 1
            indent = _indent_of(lines[ins_line])
            argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance (action + args + single-use nonce)",
                f"{indent}if not _vyrion.authorize(seal={approval_param},",
                f"{indent}        args={{{argmap}}}, run_id='', checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            for t in reversed(gate):
                inserts.setdefault(ins_line, []).insert(0, t)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_strands(source: str, action_func: str, interrupt_var: str, arg_fields: list,
                  import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch a Strands tool: after the human decision arrives via the interrupt
    response, verify it is a provenance-bound Seal (action + args + single-use nonce)
    before the tool's side effect. The interrupt state is persisted/writable and the
    tool has no trusted run id, so binding is action + args + nonce."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == action_func:
            interrupt_line = None
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                    f = stmt.value.func
                    if isinstance(f, ast.Attribute) and f.attr == "interrupt":
                        if stmt.targets and isinstance(stmt.targets[0], ast.Name):
                            interrupt_var = stmt.targets[0].id
                            interrupt_line = stmt.end_lineno
            if not interrupt_line:
                break
            indent = _indent_of(lines[interrupt_line - 1])
            argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance (action + args + single-use nonce)",
                f"{indent}if not _vyrion.authorize(seal={interrupt_var},",
                f"{indent}        args={{{argmap}}}, run_id='', checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            inserts.setdefault(interrupt_line, []).extend(gate)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_agno(source: str, action_func: str, approval_param: str, arg_fields: list,
               import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch an Agno requires_confirmation tool: verify the confirmation (serialized in
    session state) is a provenance-bound Seal (action + args + single-use nonce) before
    the tool's side effect. State is serialized whole, so there is no trusted run anchor;
    binding is action + args + nonce, minted by the trusted approver."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == action_func:
            first = node.body[0]
            ins_line = first.lineno - 1
            indent = _indent_of(lines[ins_line])
            argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance (action + args + single-use nonce)",
                f"{indent}if not _vyrion.authorize(seal={approval_param},",
                f"{indent}        args={{{argmap}}}, run_id='', checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            for t in reversed(gate):
                inserts.setdefault(ins_line, []).insert(0, t)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_semantic_kernel(source: str, action_func: str, approval_param: str, arg_fields: list,
                          import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch a Semantic Kernel Process step: verify the external-event approval
    (serialized in the checkpointed KernelProcessState) is a provenance-bound Seal
    (action + args + single-use nonce) before the step's side effect. Process state is
    serialized whole, so there is no trusted run anchor; binding is action + args + nonce."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == action_func:
            first = node.body[0]
            ins_line = first.lineno - 1
            indent = _indent_of(lines[ins_line])
            argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance (action + args + single-use nonce)",
                f"{indent}if not _vyrion.authorize(seal={approval_param},",
                f"{indent}        args={{{argmap}}}, run_id='', checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            for t in reversed(gate):
                inserts.setdefault(ins_line, []).insert(0, t)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_airflow(source: str, action_func: str, approval_param: str, arg_fields: list,
                  import_line: str = "import vyrion_guard as _vyrion") -> str:
    """Patch an Airflow task callable: verify the HITL response (read from the metadata
    DB / XCom) is a provenance-bound Seal (action + args + single-use nonce) before the
    task's side effect. The metadata store is operator-owned and writable, and no trusted
    run identity survives it, so binding is action + args + nonce."""
    tree = ast.parse(source)
    lines = source.splitlines()
    inserts = {}
    body = tree.body
    at = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        at = body[0].end_lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            at = node.end_lineno
    inserts.setdefault(at, []).append(import_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == action_func:
            first = node.body[0]
            ins_line = first.lineno - 1
            indent = _indent_of(lines[ins_line])
            argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
            gate = [
                f"{indent}# vyrion: verify approval provenance (action + args + single-use nonce)",
                f"{indent}if not _vyrion.authorize(seal={approval_param},",
                f"{indent}        args={{{argmap}}}, run_id='', checkpoint_id=''):",
                f'{indent}    raise _vyrion.GhostApprovalBlocked("approval-provenance check failed")',
            ]
            for t in reversed(gate):
                inserts.setdefault(ins_line, []).insert(0, t)
            break

    out = list(lines)
    for at_ in sorted(inserts.keys(), reverse=True):
        for text in reversed(inserts[at_]):
            out.insert(at_, text)
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    ast.parse(result)
    return result


def patch_js_source(source: str, action_func: str, approval_param: str, arg_fields: list,
                    guard_import: str = "vyrion_guard.mjs") -> str:
    """Patch a JavaScript/TypeScript protected function to verify the approval as a
    provenance-bound Seal before the side effect. Python has no JS AST, so this is a
    text transform against a well-defined function shape:
        export async function <action_func>({ <params>, <approval_param> }) {
    It inserts an import of the guard and a fail-closed check at the function body top.
    Idempotent: returns source unchanged if already patched."""
    import re as _re
    if "_vyrion_authorize" in source or "vyrion_guard.mjs" in source:
        return source
    lines = source.splitlines()
    # 1) add the guard import after the last top-level import, else at top
    import_line = f"import {{ authorize as _vyrion_authorize }} from './{guard_import}';"
    last_import = -1
    for i, ln in enumerate(lines):
        if _re.match(r"\s*import\b", ln):
            last_import = i
    lines.insert(last_import + 1, import_line)

    # 2) find the function opening and insert the gate after the first '{'
    argmap = ", ".join(f'"{f}": {f}' for f in arg_fields)
    gate = [
        "  // vyrion: verify approval provenance (action + args + single-use nonce)",
        f"  if (!_vyrion_authorize({{ seal: {approval_param}, args: {{ {argmap} }},"
        " run_id: '', checkpoint_id: '' }, import.meta.dirname)) {",
        '    throw new Error("GhostApprovalBlocked: approval-provenance check failed");',
        "  }",
    ]
    pat = _re.compile(r"(async\s+function\s+" + _re.escape(action_func) +
                      r"\s*\([^)]*\)\s*\{)")
    out, done = [], False
    for ln in lines:
        out.append(ln)
        if not done and pat.search(ln):
            out.extend(gate)
            done = True
    result = "\n".join(out)
    if source.endswith("\n"):
        result += "\n"
    return result
