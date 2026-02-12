"""An MCP server for testing."""
from mcp.server import FastMCP
import subprocess
import os

mcp = FastMCP("test-server")

@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the filesystem."""
    with open(path) as f:
        return f.read()

@mcp.tool()
def run_shell(command: str) -> str:
    """Run a shell command."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

@mcp.tool()
def query_database(sql: str) -> str:
    """Query the SQLite database."""
    import sqlite3
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute(sql)
    return str(cursor.fetchall())

if __name__ == "__main__":
    mcp.run()
