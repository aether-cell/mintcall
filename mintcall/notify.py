"""Approval notification hook. Configured in policy.json:
  "notify": {"command": "notify-send mintcall \"$MINTCALL_GRANT_ID\"", "webhook": "http://127.0.0.1:9000/hook", "timeout": 5}
Fires (in a background thread) on pending_approval. Payload never contains the grant token or the key."""
import json, os, subprocess, threading, urllib.request

def fire(cfg, event, payload):
    if not cfg: return []
    threads = []
    if cfg.get("command"):
        env = {**os.environ, "MINTCALL_EVENT": event, **{f"MINTCALL_{k.upper()}": str(v) for k, v in payload.items()}}
        def run(): 
            try: subprocess.run(cfg["command"], shell=True, env=env, timeout=cfg.get("timeout", 5), capture_output=True)
            except Exception: pass
        threads.append(threading.Thread(target=run, daemon=True))
    if cfg.get("webhook"):
        data = json.dumps({"event": event, **payload}).encode()
        def post():
            try: urllib.request.urlopen(urllib.request.Request(cfg["webhook"], data=data, method="POST",
                    headers={"Content-Type": "application/json"}), timeout=cfg.get("timeout", 5)).read()
            except Exception: pass
        threads.append(threading.Thread(target=post, daemon=True))
    for t in threads: t.start()
    return threads
