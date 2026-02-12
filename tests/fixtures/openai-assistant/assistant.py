"""An OpenAI assistant for testing."""
from openai import OpenAI
import os

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

assistant = client.beta.assistants.create(
    name="Research Assistant",
    instructions="Help users with research tasks.",
    model="gpt-4",
    tools=[{"type": "code_interpreter"}, {"type": "file_search"}],
)

thread = client.beta.threads.create()

message = client.beta.threads.messages.create(
    thread_id=thread.id,
    role="user",
    content="Analyze this dataset"
)

run = client.beta.threads.runs.create(
    thread_id=thread.id,
    assistant_id=assistant.id,
)
