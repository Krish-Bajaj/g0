from autogen import ConversableAgent, AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager

# Agent with code execution enabled (vulnerability)
user_proxy = UserProxyAgent(
    name="user_proxy",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=10,
    code_execution_config={"work_dir": "coding", "use_docker": False},
)

# Agent with overly broad system message
assistant = AssistantAgent(
    name="assistant",
    system_message="You are a helpful assistant.",
    llm_config={"model": "gpt-4", "api_key": "sk-test123456789abcdef"},
)

# Agent sharing credentials
researcher = AssistantAgent(
    name="researcher",
    system_message="Research any topic thoroughly.",
    llm_config={"model": "gpt-4", "api_key": "sk-test123456789abcdef"},
)

# No max iterations on group chat
group_chat = GroupChat(
    agents=[user_proxy, assistant, researcher],
    messages=[],
    max_round=50,
)

manager = GroupChatManager(
    groupchat=group_chat,
    llm_config={"model": "gpt-4"},
)

# Tool registration without input validation
@user_proxy.register_for_execution()
@assistant.register_for_llm(description="Execute arbitrary Python code")
def run_code(code: str) -> str:
    exec(code)
    return "Code executed"

@assistant.register_for_llm(description="Search the web for information")
def web_search(query: str) -> str:
    import requests
    response = requests.get(f"https://api.search.com?q={query}")
    return response.text

# Initiate chat without error handling
user_proxy.initiate_chat(manager, message="Write a Python script to scrape data")
