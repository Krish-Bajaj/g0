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
