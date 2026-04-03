import type { VercelRequest, VercelResponse } from '@vercel/node';
import Groq from 'groq-sdk';

let groq: Groq | null = null;

function initGroq() {
  if (!groq && process.env.GROQ_API_KEY) {
    groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
  }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  initGroq();

  const { messages } = req.body;

  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Messages array is required' });
  }

  if (!groq) {
    return res.status(503).json({ error: 'AI service is currently unavailable. Please check the GROQ_API_KEY.' });
  }

  try {
    const completion = await groq.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: 'You are Risk Analyzer AI, a specialized cybersecurity assistant. Your goal is to help users understand phishing threats, identify suspicious URLs, and provide security best practices. Keep your answers concise, professional, and helpful. If a user asks about a specific URL, remind them to use the main Dashboard scanner for a deep heuristic analysis.'
        },
        ...messages
      ],
      model: 'llama-3.3-70b-versatile',
    });

    const aiResponse = completion.choices[0]?.message?.content || "I'm sorry, I couldn't process that request.";
    return res.json({ content: aiResponse });
  } catch (error: any) {
    console.error('Groq Chat Error:', error);
    return res.status(500).json({ error: 'Failed to connect to AI service' });
  }
}