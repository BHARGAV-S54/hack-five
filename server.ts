import express from "express";
import { createServer as createViteServer } from "vite";
import Groq from "groq-sdk";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
let groq: Groq | null = null;
if (process.env.GROQ_API_KEY) {
  groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
} else {
  console.warn("⚠️  GROQ_API_KEY is missing. AI analysis will be unavailable.");
}

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  app.use(express.json());

  // --- AI Assistant Chat Endpoint ---
  app.post("/api/chat", async (req, res) => {
    const { messages } = req.body;

    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: "Messages array is required" });
    }

    if (!groq) {
      return res.status(503).json({ error: "AI service is currently unavailable. Please check the GROQ_API_KEY." });
    }

    try {
      const completion = await groq.chat.completions.create({
        messages: [
          {
            role: "system",
            content: "You are Risk Analyzer AI, a specialized cybersecurity assistant. Your goal is to help users understand phishing threats, identify suspicious URLs, and provide security best practices. Keep your answers concise, professional, and helpful. If a user asks about a specific URL, remind them to use the main Dashboard scanner for a deep heuristic analysis."
          },
          ...messages
        ],
        model: "llama-3.3-70b-versatile",
      });

      const aiResponse = completion.choices[0]?.message?.content || "I'm sorry, I couldn't process that request.";
      res.json({ content: aiResponse });
    } catch (error: any) {
      console.error("Groq Chat Error:", error);
      res.status(500).json({ error: "Failed to connect to AI service" });
    }
  });

  // --- Analysis Logic (The "Backend Logic") ---
  app.post("/api/analyze", async (req, res) => {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    try {
      // 1. Heuristic Checks
      let urlScore = 0;
      let sslScore = 0;
      let behaviorScore = 0;
      const findings: string[] = [];
      const lowerUrl = url.toLowerCase();

      // SSL Check
      if (!lowerUrl.startsWith("https://")) {
        sslScore = 80;
        findings.push("Missing HTTPS: Connection is not secure.");
      } else {
        sslScore = 10; // Low risk if HTTPS
      }

      // URL Analysis
      if (url.length > 75) {
        urlScore += 30;
        findings.push("URL Length: Unusually long URL.");
      }
      if (url.includes("@")) {
        urlScore += 40;
        findings.push("Special Characters: Contains '@'.");
      }
      const dashCount = (url.match(/-/g) || []).length;
      if (dashCount > 3) {
        urlScore += 20;
        findings.push("Excessive Hyphens: Potential typosquatting.");
      }
      urlScore = Math.min(100, urlScore);

      // Behavioral (Keywords)
      const keywords = ["login", "verify", "bank", "secure", "update", "account", "signin", "wp-admin", "pay", "wallet"];
      const foundKeywords = keywords.filter(k => lowerUrl.includes(k));
      if (foundKeywords.length > 0) {
        behaviorScore = Math.min(100, foundKeywords.length * 25);
        findings.push(`Suspicious Keywords: Found terms like ${foundKeywords.join(", ")}.`);
      }

      // 2. AI Enhancement (Groq)
      let aiData: any = {
        score: 0,
        riskLevel: "Low",
        explanation: findings.join(" "),
        recommendations: ["Avoid entering sensitive data on this site."],
        domainAge: "Unknown (AI estimation unavailable)",
        urlScore: urlScore,
        sslScore: sslScore,
        behaviorScore: behaviorScore,
        urlAnalysis: findings.filter(f => f.includes("URL") || f.includes("Hyphens") || f.includes("Characters")).join(" ") || "URL structure appears standard.",
        sslAnalysis: findings.find(f => f.includes("HTTPS")) || "SSL/HTTPS is present and active.",
        behaviorAnalysis: findings.find(f => f.includes("Keywords")) || "No suspicious behavioral keywords detected."
      };

      if (groq) {
        try {
          const prompt = `Analyze this URL for phishing risks: ${url}. 
          Heuristic findings: ${findings.join("; ")}.
          Initial scores: URL:${urlScore}, SSL:${sslScore}, Behavior:${behaviorScore}.
          
          Please provide the analysis in strict JSON format with these fields:
          - score (overall risk number 0-100)
          - riskLevel (Low, Medium, High, Critical)
          - explanation (string - a detailed verdict)
          - domainAge (string)
          - recommendations (array of strings)
          - urlScore (number 0-100)
          - sslScore (number 0-100)
          - behaviorScore (number 0-100)
          - urlAnalysis (string - detailed technical analysis of the URL structure)
          - sslAnalysis (string - detailed analysis of the SSL/Security status)
          - behaviorAnalysis (string - detailed analysis of the behavioral patterns)
          
          Do not include markdown formatting or any other text. Just the JSON object.`;

          const completion = await groq.chat.completions.create({
            messages: [
              {
                role: "user",
                content: prompt,
              },
            ],
            model: "llama-3.3-70b-versatile",
            response_format: { type: "json_object" }
          });

          const responseText = completion.choices[0]?.message?.content;
          if (responseText) {
            aiData = JSON.parse(responseText);
          }
        } catch (aiError: any) {
          console.error("AI Analysis Error:", aiError);
          aiData.explanation = `AI analysis unavailable. Heuristic findings: ${findings.join(" ")}`;
          aiData.score = Math.max(urlScore, sslScore, behaviorScore);
          aiData.riskLevel = aiData.score > 75 ? "Critical" : aiData.score > 50 ? "High" : aiData.score > 25 ? "Medium" : "Low";
        }
      }

      // Combine Results
      const finalScore = aiData.score || Math.max(urlScore, sslScore, behaviorScore);
      
      res.json({
        url,
        score: finalScore,
        riskLevel: aiData.riskLevel,
        urlAnalysis: aiData.urlAnalysis,
        sslAnalysis: aiData.sslAnalysis,
        behaviorAnalysis: aiData.behaviorAnalysis,
        urlScore: aiData.urlScore || urlScore,
        sslScore: aiData.sslScore || sslScore,
        behaviorScore: aiData.behaviorScore || behaviorScore,
        verdict: aiData.explanation,
        domainAge: aiData.domainAge,
        recommendations: aiData.recommendations,
        timestamp: Date.now()
      });

    } catch (error: any) {
      console.error("Backend Analysis Error:", error);
      res.status(500).json({ 
        error: "Internal server error during analysis.",
        details: error.message 
      });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    
    // SPA Fallback: Serve index.html for any unknown routes
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
