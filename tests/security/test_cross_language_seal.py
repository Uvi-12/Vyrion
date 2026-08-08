"""A Python-minted Seal must canonicalize and verify identically in Node.

This is the guarantee that lets one Seal cover both Python and JavaScript frameworks:
the canonical bytes are identical across languages, and Node's crypto verifies the
Ed25519 signature over them. If Node is not available, the test skips rather than fails.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from vyrion.protocol import (
    ApprovalBroker,
    Approver,
    WorkflowRef,
    ExecutionRef,
    new_keypair,
)

_NODE = shutil.which("node")

_VERIFY_JS = r"""
import { readFileSync } from 'fs';
import crypto from 'crypto';
function fmt(n){ if(!isFinite(n)) throw new Error('nf'); return String(n); }
function esc(s){ let o='"'; for(const c of s){ const k=c.codePointAt(0);
  if(c==='"')o+='\\"'; else if(c==='\\')o+='\\\\'; else if(k===8)o+='\\b';
  else if(k===9)o+='\\t'; else if(k===10)o+='\\n'; else if(k===12)o+='\\f';
  else if(k===13)o+='\\r'; else if(k<32)o+='\\u'+k.toString(16).padStart(4,'0'); else o+=c; }
  return o+'"'; }
function canon(v){ if(v===null)return 'null'; if(typeof v==='boolean')return v?'true':'false';
  if(typeof v==='number')return fmt(v); if(typeof v==='string')return esc(v);
  if(Array.isArray(v))return '['+v.map(canon).join(',')+']';
  return '{'+Object.keys(v).sort().map(k=>esc(k)+':'+canon(v[k])).join(',')+'}'; }
const seal = JSON.parse(readFileSync(process.argv[2],'utf8'));
const { signature, ...signing } = seal;
const payload = Buffer.from(canon(signing),'utf8');
const same = Buffer.compare(payload, readFileSync(process.argv[3])) === 0;
const pub = crypto.createPublicKey(readFileSync(process.argv[4]));
const ok = crypto.verify(null, payload, pub, Buffer.from(signature,'hex'));
console.log(JSON.stringify({ bytes_identical: same, verified: ok }));
"""


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_python_seal_verifies_in_node(tmp_path: Path):
    signer = new_keypair("key-1")
    (tmp_path / "pub.pem").write_bytes(signer.public_pem())
    broker = ApprovalBroker(signer)
    ev = broker.issue(
        approver=Approver(subject="cfo@corp"),
        decision="approve",
        action_id="payments.transfer",
        action_fingerprint="fp",
        args={"recipient": "acct-A", "amount": 1000, "currency": "USD"},
        workflow=WorkflowRef(system="xlang", run_id="", checkpoint_id=""),
        execution=ExecutionRef(environment="production", audience="payments"),
        approval_point_id="xlang",
    )
    (tmp_path / "seal.json").write_text(json.dumps(ev.to_dict()))
    (tmp_path / "payload.bin").write_bytes(ev.signing_payload())
    (tmp_path / "verify.mjs").write_text(_VERIFY_JS)

    out = subprocess.run(
        ["node", str(tmp_path / "verify.mjs"),
         str(tmp_path / "seal.json"),
         str(tmp_path / "payload.bin"),
         str(tmp_path / "pub.pem")],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result["bytes_identical"] is True, "canonical bytes differ between Python and Node"
    assert result["verified"] is True, "Node failed to verify the Python-minted Seal"
