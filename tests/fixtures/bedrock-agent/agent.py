import boto3
import json

# Bedrock agent setup
bedrock_runtime = boto3.client('bedrock-runtime', region_name='us-east-1')
bedrock_agent = boto3.client('bedrock-agent-runtime', region_name='us-east-1')

# Direct model invocation without token limits
def invoke_model(prompt):
    response = bedrock_runtime.invoke_model(
        modelId="anthropic.claude-3-sonnet-20240229-v1:0",
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "messages": [{"role": "user", "content": prompt}],
        })
    )
    return json.loads(response['body'].read())

# Agent with system prompt from DB (vulnerability)
def create_agent():
    import sqlite3
    conn = sqlite3.connect('prompts.db')
    system_prompt = conn.execute("SELECT prompt FROM system_prompts WHERE active=1").fetchone()[0]
    
    response = bedrock_agent.invoke_agent(
        agentId='AGENT123',
        agentAliasId='ALIAS456',
        sessionId='session-001',
        inputText="Hello",
    )
    return response

# Hardcoded AWS credentials (vulnerability)
AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

# No error handling on API calls
def query_knowledge_base(query):
    result = bedrock_agent.retrieve(
        knowledgeBaseId='KB789',
        retrievalQuery={'text': query}
    )
    return result['retrievalResults']
