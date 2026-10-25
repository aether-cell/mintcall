"""Sketch of the runner side of task-id scoping. The broker never kills anything: the runner owns
teardown. The order on task end matters:

  1. broker.task_end(...)   -> the task is marked ended and its unused grants revoked, in one
                               transaction; every later mint or use bound to it gets a 403 with
                               "task ... has ended". A signed task_end receipt lists the revoked ids.
  2. os.killpg(...)          -> only then is the task's process group killed.

So a process that is still alive during teardown cannot mint or use a credential for that task.

    python examples/task_runner.py --home ./.mintcall task-7f3a2c -- python my_agent_task.py
"""
import argparse, os, signal, subprocess, sys
from datetime import datetime, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from mintcall.broker import Broker

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def run(broker, task_id, argv, destructor=None, timeout=None):
    broker.task_open({"task_id": task_id, "timestamp": now()})
    env = {**os.environ, "MINTCALL_TASK_ID": task_id}           # the agent passes this as task_id when requesting grants
    proc = subprocess.Popen(argv, env=env, start_new_session=True)  # own process group, so killpg reaches every child
    try: proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired: pass
    ok = True
    if destructor is not None:
        try: destructor()
        except Exception: ok = False
    end = broker.task_end({"task_id": task_id, "timestamp": now(), "destructorOk": ok})  # 1. refuse first
    try: os.killpg(proc.pid, signal.SIGKILL)                                            # 2. then tear down
    except ProcessLookupError: pass
    proc.wait()
    return end

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--home", default=os.path.expanduser("~/.mintcall"))
    ap.add_argument("--timeout", type=float); ap.add_argument("task_id"); ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(); cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    print(run(Broker(a.home), a.task_id, cmd, timeout=a.timeout))
