"""Sketch of the runner side of task-id scoping. The broker never kills anything: the runner owns
teardown. The order on task end matters:

  1. broker.task_end(...)   -> the task is marked ended and its unused grants revoked, in one
                               transaction; every later mint or use bound to it gets a 403 with
                               "task ... has ended". A signed task_end receipt lists the revoked ids.
  2. os.killpg(...)          -> only then is the task's process group killed.
  3. destructor()            -> release whatever else the task held (locks, temp dirs, ...).
  4. broker.task_destroyed(...) -> the runner stamps destructorOk, a separate signed receipt.

So a process that is still alive during teardown cannot mint or use a credential for that task.
Two facts, two stamps: grantsRevoked comes from the broker (step 1), destructorOk from the runner
(step 4), because only the runner can know the process group is gone. A task with the first and not
the second is what `mintcall task stuck` (Broker.stuck_tasks) lists for a sweep.

    python examples/task_runner.py --home ./.mintcall task-7f3a2c -- python my_agent_task.py
"""
import argparse, os, signal, subprocess, sys
from datetime import datetime, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from mintcall.broker import Broker

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def run(broker, task_id, argv, destructor=None, timeout=None, transition="done"):
    broker.task_open({"task_id": task_id, "timestamp": now()})
    env = {**os.environ, "MINTCALL_TASK_ID": task_id}           # the agent passes this as task_id when requesting grants
    proc = subprocess.Popen(argv, env=env, start_new_session=True)  # own process group, so killpg reaches every child
    try: proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired: pass
    end = broker.task_end({"task_id": task_id, "timestamp": now(), "transition": transition})  # 1. refuse first
    try: os.killpg(proc.pid, signal.SIGKILL)                                                  # 2. then tear down
    except ProcessLookupError: pass
    proc.wait()
    ok = True
    try: os.killpg(proc.pid, 0); ok = False      # group still has members: teardown did not finish
    except ProcessLookupError: pass
    except PermissionError: ok = False
    if destructor is not None:                                                                # 3. release the rest
        try: destructor()
        except Exception: ok = False
    destroyed = broker.task_destroyed({"task_id": task_id, "timestamp": now(), "destructorOk": ok})  # 4. stamp
    return {**end, "destroyed": destroyed}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--home", default=os.path.expanduser("~/.mintcall"))
    ap.add_argument("--timeout", type=float); ap.add_argument("task_id"); ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(); cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    print(run(Broker(a.home), a.task_id, cmd, timeout=a.timeout))
