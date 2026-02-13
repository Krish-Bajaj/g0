import { generateText, streamText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';

const weatherTool = tool({
  description: 'Get weather for a location',
  parameters: z.object({
    location: z.string(),
  }),
  execute: async ({ location }) => {
    const response = await fetch(`https://api.weather.com/v1?q=${location}`);
    return response.json();
  },
});

export async function handleChat(userMessage: string, userName: string) {
  const result = await generateText({
    model: openai('gpt-4'),
    system: `You are a helpful assistant for ${userName}. Answer any question.`,
    prompt: userMessage,
    tools: { weather: weatherTool },
    maxTokens: 4096,
  });
  return result.text;
}

export async function streamChat(messages: any[]) {
  const result = await streamText({
    model: openai('gpt-4-turbo'),
    system: 'You are an assistant.',
    messages,
  });
  return result.toAIStreamResponse();
}
