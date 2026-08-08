"""Native adapter for the Vercel AI SDK (Node/TypeScript tool confirmation HITL).

A Vercel AI SDK tool requires human confirmation; on resume the confirmation is trusted
and the tool runs. A writer of the persisted message/tool-result state can inject a
confirmation with no binding to approver, action, arguments, or a single-use nonce (the
Ghost Approval surface). The Seal is language-agnostic: the JS guard verifies a
Python-minted Seal byte-for-byte. No trusted run identity survives the serialized state,
so binding is action + arguments + a single-use nonce.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from .genkit import GenkitNativeAdapter
from ..contract import DetectionEvidence


class VercelAINativeAdapter(GenkitNativeAdapter):
    framework = "Vercel AI"
    native_package = "vyrion-vercel-ai"
    host_requirements = "npm install ai  (Vercel AI SDK, Node >= 18)"
    _guard_filename = "vyrion_guard.mjs"
    _sample_filename = "payment_agent.mjs"
    _sample_dir = "vercel_ai"
    _system = "vercel-ai"
    _approval_point = "vercel-ai-approval"
    _framework_key = "vercel_ai"          # registry key / manifest framework
    _node_pkg = "ai"                      # the npm package name

    _AI_IMPORT = re.compile(r"""(from\s+['"]ai['"]|require\(\s*['"]ai['"]\s*\))""")

    def _import_token(self):
        return "ai"

    def detect_project(self, project):
        hits = []
        for path in self._src_files(project):
            text = Path(path).read_text()
            if self._AI_IMPORT.search(text):
                for i, ln in enumerate(text.splitlines(), 1):
                    if self._AI_IMPORT.search(ln):
                        hits.append(self._ev(path, i, ln, "vercel-ai import"))
                        break
        return DetectionEvidence(detected=bool(hits), framework=self.framework, evidence=hits)

    def _find_node_modules(self, project):
        proj = Path(project)
        cands = [proj / "node_modules"]
        env = os.environ.get("VYRION_VERCEL_AI_NODE_MODULES") or os.environ.get("VYRION_NODE_MODULES")
        if env:
            cands.append(Path(env))
        cands.append(Path("/tmp/vercel_probe/node_modules"))
        for c in cands:
            if (c / self._node_pkg).exists():
                return str(c)
        return None

    def detect_version(self, project):
        cands = [Path(project) / "node_modules" / self._node_pkg / "package.json"]
        nm = self._find_node_modules(project)
        if nm:
            cands.append(Path(nm) / self._node_pkg / "package.json")
        for cand in cands:
            if cand.exists():
                try:
                    import json
                    return json.loads(cand.read_text()).get("version", "unknown")
                except Exception:
                    pass
        return "unknown"
