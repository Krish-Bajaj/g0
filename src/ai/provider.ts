export interface AIProvider {
  name: string;
  analyze(prompt: string, context: string): Promise<string>;
}

export function getAIProvider(): AIProvider | null {
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  if (anthropicKey) {
    return createAnthropicProvider(anthropicKey);
  }

  const openaiKey = process.env.OPENAI_API_KEY;
  if (openaiKey) {
    return createOpenAIProvider(openaiKey);
  }

  return null;
}

function createAnthropicProvider(apiKey: string): AIProvider {
  return {
    name: 'anthropic',
    async analyze(prompt: string, context: string): Promise<string> {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5',
          max_tokens: 4096,
          messages: [
            { role: 'user', content: `${prompt}\n\n${context}` },
          ],
        }),
      });

      if (!response.ok) {
        throw new Error(`Anthropic API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as { content: Array<{ text: string }> };
      return data.content[0]?.text ?? '';
    },
  };
}

function createOpenAIProvider(apiKey: string): AIProvider {
  return {
    name: 'openai',
    async analyze(prompt: string, context: string): Promise<string> {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: 'gpt-5-mini',
          max_tokens: 4096,
          messages: [
            { role: 'system', content: prompt },
            { role: 'user', content: context },
          ],
        }),
      });

      if (!response.ok) {
        throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as { choices: Array<{ message: { content: string } }> };
      return data.choices[0]?.message?.content ?? '';
    },
  };
}
