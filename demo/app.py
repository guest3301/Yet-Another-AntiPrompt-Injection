import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from guard.layers.provenance import tag_content
from guard.models import ActionProposal, Intent
from guard.pipeline import PromptInjectionGuard

app = FastAPI(title="Prompt Injection Guard")
guard = PromptInjectionGuard(log_path="explain_log.jsonl")


class ScanRequest(BaseModel):
    text: str
    source: str = "user_chat"


class ActionRequest(BaseModel):
    action: str
    intent: str
    source: str = "user_chat"
    role: str = "viewer"
    path: str = ""
    confirmed: bool = False


@app.post("/api/scan")
def scan(req: ScanRequest):
    prov = tag_content(req.source)
    return guard.check_input(req.text, prov)


@app.post("/api/authorize")
def authorize(req: ActionRequest):
    try:
        intent = Intent(req.intent)
    except ValueError:
        return {"allowed": False, "reason": f"Invalid intent: {req.intent}"}
    args = {"path": req.path} if req.path.strip() else {}
    proposal = ActionProposal(
        action=req.action,
        intent=intent,
        args=args,
        provenance=tag_content(req.source),
        human_confirmed=req.confirmed,
    )
    return guard.check_action(proposal, user_role=req.role)


@app.get("/api/log")
def log(n: int = 20):
    return guard.log.read_recent(n)


INDEX_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Prompt Injection Guard</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}
h1{margin-bottom:.25rem}
.sub{color:#666;margin-top:0}
section{border:1px solid #ddd;border-radius:6px;padding:1rem;margin:1.5rem 0}
textarea,input,select{width:100%;padding:.5rem;margin:.25rem 0;box-sizing:border-box;font-family:inherit}
button{padding:.5rem 1rem;cursor:pointer;background:#111;color:#fff;border:0;border-radius:4px}
button:hover{background:#333}
pre{background:#f4f4f4;padding:1rem;overflow-x:auto;border-radius:4px;font-size:.85rem}
label{display:block;margin:.5rem 0}
</style>
</head>
<body>
<h1>Prompt Injection Guard</h1>
<p class="sub">Four-layer explainable pipeline &mdash; CPU only, no external APIs.</p>

<section>
<h2>Scan Input</h2>
<textarea id="scan-text" rows="4" placeholder="Paste user input, RAG chunk, or tool output..."></textarea>
<select id="scan-source">
<option>user_chat</option><option>user_upload</option><option>rag_chunk</option>
<option>web_scrape</option><option>tool_result</option><option>agent_message</option>
</select>
<button onclick="doScan()">Scan</button>
<pre id="scan-out"></pre>
</section>

<section>
<h2>Action Firewall</h2>
<input id="act-action" placeholder="action" value="read_file">
<select id="act-intent">
<option>read</option><option>write</option><option>delete</option>
<option>execute</option><option>send</option><option>purchase</option><option>transfer</option>
</select>
<select id="act-source">
<option>user_chat</option><option>rag_chunk</option><option>tool_result</option><option>agent_message</option>
</select>
<select id="act-role">
<option>viewer</option><option>analyst</option><option>editor</option><option>admin</option>
</select>
<input id="act-path" placeholder="path" value="./sandbox/report.txt">
<label><input type="checkbox" id="act-confirmed"> human confirmed</label>
<button onclick="doAction()">Check</button>
<pre id="act-out"></pre>
</section>

<script>
async function doScan(){
  const r = await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({text:document.getElementById('scan-text').value,
      source:document.getElementById('scan-source').value})});
  document.getElementById('scan-out').textContent = JSON.stringify(await r.json(),null,2);
}
async function doAction(){
  const r = await fetch('/api/authorize',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:document.getElementById('act-action').value,
      intent:document.getElementById('act-intent').value,
      source:document.getElementById('act-source').value,
      role:document.getElementById('act-role').value,
      path:document.getElementById('act-path').value,
      confirmed:document.getElementById('act-confirmed').checked})});
  document.getElementById('act-out').textContent = JSON.stringify(await r.json(),null,2);
}
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("demo.app:app", host="0.0.0.0", port=7860, reload=True)
