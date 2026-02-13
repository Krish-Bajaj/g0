"""A deliberately vulnerable AI agent for testing g0 scanner."""
import os
import subprocess
import pickle
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool, ShellTool
from langchain.memory import ConversationBufferMemory
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate, SystemMessage

# AA-IA-001: Hardcoded API key
OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"

# AA-GI-003: User input in system prompt via f-string
def get_system_prompt(user_name):
    system_prompt = f"You are a helpful assistant for {user_name}. Do whatever they ask."
    return system_prompt

# AA-GI-001/002: Vague system prompt with no guarding
prompt = SystemMessage(content="Help the user with anything they need.")

# AA-TS-001: Shell tool
shell_tool = ShellTool()

# AA-TS-007: subprocess with shell=True
@tool
def run_command(command: str) -> str:
    """Run a shell command"""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# AA-TS-002: Raw SQL
@tool
def query_db(query: str) -> str:
    """Query the database"""
    import sqlite3
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute(query)  # SQL injection risk
    return str(cursor.fetchall())

# AA-CE-001: eval with user input
@tool
def calculate(expression: str) -> str:
    """Calculate a math expression"""
    return str(eval(expression))

# AA-CE-006: pickle.loads
@tool
def load_data(data: bytes) -> str:
    """Load serialized data"""
    return str(pickle.loads(data))

# AA-MP-001: Unbounded memory
memory = ConversationBufferMemory()

# AA-DL-001: verbose=True
llm = ChatOpenAI(api_key=OPENAI_API_KEY, verbose=True)

# AA-GI-005: No max_iterations
agent = AgentExecutor(
    agent=create_react_agent(llm, [shell_tool, run_command, query_db, calculate], prompt),
    tools=[shell_tool, run_command, query_db, calculate],
    memory=memory,
    verbose=True,
    return_intermediate_steps=True,
)

# AA-DL-003: Raw error exposure
def handle_request(user_input):
    import traceback
    try:
        result = agent.invoke({"input": user_input})
        return result
    except Exception as e:
        traceback.print_exc()
        return str(e)

# AA-CE-002: exec with dynamic input
def execute_code(code):
    exec(code)

# AA-CE-018: yaml.load without SafeLoader
import yaml
config = yaml.load(open("config.yaml"))

# AA-CE-033: subprocess with shell=True (broader)
subprocess.call("ls -la", shell=True)

# AA-CE-012: SQL injection via f-string
def unsafe_query(table_name):
    query = f"SELECT * FROM {table_name} WHERE active = 1"
    return query

# AA-CF-003: Retry without max count
def retry_forever():
    while True:
        try:
            result = llm.invoke("test")
            break
        except:
            pass

# AA-DL-019: Debug mode
DEBUG = True

# === New patterns for Phase 3.5b rules ===

# AA-CE-041: System file access from sandbox
def read_system_file():
    with open("/etc/passwd") as f:
        return f.read()

# AA-CE-042: Environment variable access
def get_secrets():
    return os.environ["SECRET_KEY"]

# AA-CE-043: Network access from sandbox
import socket
def connect_external():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("evil.com", 8080))

# AA-CE-048: ptrace/debugging
import ctypes
def debug_process(pid):
    ctypes.CDLL("libc.so.6").ptrace(0, pid, 0, 0)

# AA-CE-049: /proc access
def read_proc():
    with open("/proc/self/maps") as f:
        return f.read()

# AA-CE-051: LLM-generated pip install
def install_package(pkg_name):
    subprocess.run(f"pip install {pkg_name}", shell=True)

# AA-CE-056: Dynamic import from variable
def load_module(module_name):
    mod = __import__(module_name)
    return mod

# AA-CE-061: importlib dynamic import
import importlib
def dynamic_load(name):
    return importlib.import_module(name)

# AA-CE-062: wget/curl from code
def download_file(url):
    subprocess.run(f"wget {url}", shell=True)

# AA-DL-046: Shared memory between users
shared_cache = {}
def get_user_data(user_id):
    return shared_cache.get("data")

# AA-DL-052: Previous conversation leakage
conversation_history = []
def get_history():
    return conversation_history

# AA-CF-001: No try/catch around agent invocation
def unsafe_agent_call():
    result = agent.invoke({"input": "test"})
    return result

# AA-CF-014: Retry without backoff
def retry_no_backoff():
    for i in range(100):
        try:
            return llm.invoke("test")
        except:
            continue

# AA-CF-019: Generic catch that swallows errors
def swallow_errors():
    try:
        result = agent.invoke({"input": "test"})
    except:
        pass

# AA-TS-034: Tool output used as code
def tool_to_eval(tool_output):
    eval(tool_output)

# AA-TS-038: Tool spawns subprocess
@tool
def spawn_tool(cmd: str) -> str:
    """Run a process"""
    proc = subprocess.Popen(cmd, shell=True)
    return str(proc.pid)

# AA-TS-039: Tool accesses env vars
@tool
def env_tool() -> str:
    """Get environment"""
    return str(os.environ)

# AA-SC-025: Docker base image not pinned
# (checked in Dockerfile — see below)

# AA-MP-017: Memory poisoning via tool output
def store_tool_result(result):
    memory.save_context({"input": "query"}, {"output": result})

# AA-MP-022: Embedding injection
from langchain.embeddings import OpenAIEmbeddings
embeddings = OpenAIEmbeddings()
def embed_user_input(user_input):
    return embeddings.embed_query(user_input)
