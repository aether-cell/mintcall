"""Wrapping an MCP server's outbound API call with mintcall.

Before: the MCP server read WEATHER_API_KEY from mcp.json and called the API directly.
After:  mcp.json holds no secret. Each tool invocation requests a grant for exactly the call
        it is about to make, then sends it through the local mintcall proxy, which injects the key.

Works with the official `mcp` Python SDK (FastMCP) if installed; otherwise runs the same tool
function directly so you can see the flow:  python examples/mcp_tool_wrapper.py
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from mintcall.broker import Broker
from mintcall.client import call_via_proxy
from mintcall.agents import AgentKey

HOME = os.path.expanduser(os.environ.get("MINTCALL_HOME", "~/.mintcall"))
API = os.environ.get("DEMO_API", "http://127.0.0.1:9901")
# Agent signing key created by `mintcall agent add demo-agent --out PATH`; one key per agent, never shared.
AGENT_KEY = AgentKey.load(os.environ.get("MINTCALL_AGENT_KEY", os.path.expanduser("~/.mintcall-agent/demo-agent.key")))
# The agent side never opens the vault: no passphrase, no key in this process.
_broker = Broker(HOME)

def get_forecast(city: str) -> str:
    """MCP tool body: the only change vs. a normal server is call_via_proxy instead of requests.get(..., headers={key})."""
    url = f"{API}/v1/forecast?city={city}"
    r = call_via_proxy(_broker, AGENT_KEY, "demo-api", "GET", url, scope=["read"], cap=0.1, ttl=30,
                       intent={"tool": "get_forecast", "why": f"user asked weather for {city}"})
    return json.dumps(r)

try:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("weather-via-mintcall")
    mcp.tool()(get_forecast)
except ImportError:
    mcp = None

if __name__ == "__main__":
    if mcp and "--serve" in sys.argv: mcp.run()
    else: print(get_forecast(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "Prague"))
