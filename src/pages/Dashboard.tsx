import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  History, 
  Lock, 
  Globe, 
  AlertTriangle,
  Info,
  ChevronRight,
  Activity,
  Zap,
  ArrowRight,
  Loader2
} from 'lucide-react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer
} from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

interface AnalysisResult {
  url: string;
  score: number;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  urlAnalysis: string;
  sslAnalysis: string;
  behaviorAnalysis: string;
  urlScore: number;
  sslScore: number;
  behaviorScore: number;
  verdict: string;
  domainAge: string;
  recommendations: string[];
  timestamp: number;
}

const RiskGauge = ({ score }: { score: number }) => {
  const data = [
    { name: 'Risk', value: score },
    { name: 'Safe', value: 100 - score },
  ];

  const COLORS = [
    score > 75 ? '#ef4444' : score > 40 ? '#f59e0b' : '#10b981',
    '#1f2937'
  ];

  return (
    <div className="h-48 w-48 relative">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            startAngle={180}
            endAngle={0}
            paddingAngle={0}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} stroke="none" />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pt-8">
        <span className="text-4xl font-bold font-mono">{score}</span>
        <span className="text-xs uppercase tracking-widest opacity-50">Risk Score</span>
      </div>
    </div>
  );
};

export default function Dashboard() {
  const [url, setUrl] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStep, setAnalysisStep] = useState(0);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const steps = [
    "Initializing Analysis Engine...",
    "Checking URL Heuristics...",
    "Verifying SSL Certificates...",
    "Running AI Behavioral Check...",
    "Generating Security Report..."
  ];


  const analyzeUrl = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url) return;

    setIsAnalyzing(true);
    setAnalysisStep(0);
    setError(null);
    setResult(null);

    try {
      // Start the API call
      const apiPromise = fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      // Manually progress through steps to make it feel "deep"
      for (let i = 0; i < steps.length - 1; i++) {
        await new Promise(resolve => setTimeout(resolve, 800));
        setAnalysisStep(prev => prev + 1);
      }

      const response = await apiPromise;

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.details ? `${errData.error}: ${errData.details}` : errData.error || "Analysis failed");
      }

      const data = await response.json();
      
      // Final step delay
      await new Promise(resolve => setTimeout(resolve, 500));
      
      setResult(data);
      
      // Save to history
      const saved = localStorage.getItem('phishguard_history');
      const history = saved ? JSON.parse(saved) : [];
      const updated = [data, ...history.slice(0, 9)];
      localStorage.setItem('phishguard_history', JSON.stringify(updated));

    } catch (err: any) {
      console.error("Analysis Error:", err);
      setError(err.message || "Analysis failed. Please check the URL and try again.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'Low': return 'text-emerald-500';
      case 'Medium': return 'text-amber-500';
      case 'High': return 'text-orange-500';
      case 'Critical': return 'text-red-500';
      default: return 'text-gray-400';
    }
  };

  const getRiskBg = (level: string) => {
    switch (level) {
      case 'Low': return 'bg-emerald-500/10 border-emerald-500/20';
      case 'Medium': return 'bg-amber-500/10 border-amber-500/20';
      case 'High': return 'bg-orange-500/10 border-orange-500/20';
      case 'Critical': return 'bg-red-500/10 border-red-500/20';
      default: return 'bg-gray-500/10 border-gray-500/20';
    }
  };

  return (
    <div className="space-y-8">
      <section className="space-y-4">
        <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-widest text-emerald-500/80">
          <Zap className="w-3 h-3" />
          Real-time Analysis Engine
        </div>
        <h2 className="text-4xl font-bold tracking-tight">Scan for Phishing Risks</h2>
        <p className="text-gray-400 max-w-2xl">
          Enter a URL to analyze its structure, SSL certificate status, and behavioral patterns. Our AI engine cross-references known threat databases and heuristic patterns.
        </p>

        <form onSubmit={analyzeUrl} className="relative group">
          <div className="absolute -inset-1 bg-gradient-to-r from-emerald-500/20 to-blue-500/20 rounded-2xl blur opacity-25 group-focus-within:opacity-100 transition duration-1000 group-focus-within:duration-200" />
          <div className="relative flex items-center bg-[#141414] border border-white/10 rounded-xl p-2 focus-within:border-emerald-500/50 transition-all">
            <Globe className="ml-4 w-5 h-5 text-gray-500" />
            <input 
              type="text" 
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/login"
              className="flex-1 bg-transparent border-none focus:ring-0 px-4 py-3 text-lg font-mono placeholder:text-gray-600 outline-none"
            />
            <button 
              disabled={isAnalyzing || !url}
              className={cn(
                "relative overflow-hidden px-8 py-3 rounded-lg font-bold flex items-center gap-2 transition-all active:scale-95",
                isAnalyzing 
                  ? "bg-emerald-500/20 text-emerald-500 cursor-not-allowed border border-emerald-500/20" 
                  : "bg-emerald-500 hover:bg-emerald-400 text-black"
              )}
            >
              <AnimatePresence mode="wait">
                {isAnalyzing ? (
                  <motion.div
                    key="analyzing"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="flex items-center gap-2"
                  >
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Analyzing</span>
                    <motion.span
                      animate={{ opacity: [0, 1, 0] }}
                      transition={{ duration: 1.5, repeat: Infinity, times: [0, 0.5, 1] }}
                    >
                      ...
                    </motion.span>
                  </motion.div>
                ) : (
                  <motion.div
                    key="scan"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="flex items-center gap-2"
                  >
                    <Search className="w-4 h-4" />
                    <span>Scan URL</span>
                  </motion.div>
                )}
              </AnimatePresence>
              
              {isAnalyzing && (
                <motion.div 
                  className="absolute inset-0 bg-emerald-500/10"
                  initial={{ x: "-100%" }}
                  animate={{ x: "100%" }}
                  transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                  style={{
                    background: 'linear-gradient(90deg, transparent, rgba(16, 185, 129, 0.2), transparent)'
                  }}
                />
              )}
            </button>
          </div>
        </form>
        {error && (
          <motion.div 
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            className="flex items-center gap-2 text-red-400 text-sm bg-red-400/10 border border-red-400/20 p-3 rounded-lg"
          >
            <AlertTriangle className="w-4 h-4" />
            {error}
          </motion.div>
        )}
      </section>

      <AnimatePresence mode="wait">
        {result ? (
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Result Header Card */}
            <div className={cn("p-8 rounded-2xl border flex flex-col md:flex-row items-center gap-8", getRiskBg(result.riskLevel))}>
              <RiskGauge score={result.score} />
              <div className="flex-1 space-y-4 text-center md:text-left">
                <div>
                  <div className={cn("text-sm font-bold uppercase tracking-widest mb-1", getRiskColor(result.riskLevel))}>
                    {result.riskLevel} Risk Detected
                  </div>
                  <h3 className="text-2xl font-bold break-all">{result.url}</h3>
                </div>
                <p className="text-gray-300 leading-relaxed">
                  {result.verdict}
                </p>
                <div className="flex flex-wrap gap-3 justify-center md:justify-start">
                  {result.riskLevel === 'Low' ? (
                    <span className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-bold uppercase">
                      <ShieldCheck className="w-3 h-3" /> Likely Safe
                    </span>
                  ) : (
                    <span className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-red-500/20 text-red-400 text-xs font-bold uppercase">
                      <ShieldAlert className="w-3 h-3" /> Warning
                    </span>
                  )}
                  <span className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/5 text-gray-400 text-xs font-bold uppercase">
                    <History className="w-3 h-3" /> Scanned {new Date(result.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            </div>

            {/* Analysis Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-[#141414] border border-white/5 p-6 rounded-xl space-y-4 relative overflow-hidden">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-emerald-500">
                    <Globe className="w-5 h-5" />
                    <h4 className="font-bold">URL Analysis</h4>
                  </div>
                  <span className={cn("text-xs font-mono font-bold px-2 py-1 rounded bg-white/5", 
                    result.urlScore > 50 ? "text-red-400" : "text-emerald-400")}>
                    Score: {result.urlScore}
                  </span>
                </div>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {result.urlAnalysis}
                </p>
                <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden">
                  <div 
                    className={cn("h-full transition-all duration-1000", result.urlScore > 50 ? "bg-red-500" : "bg-emerald-500")}
                    style={{ width: `${result.urlScore}%` }}
                  />
                </div>
              </div>

              <div className="bg-[#141414] border border-white/5 p-6 rounded-xl space-y-4 relative overflow-hidden">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-blue-500">
                    <Lock className="w-5 h-5" />
                    <h4 className="font-bold">SSL & Security</h4>
                  </div>
                  <span className={cn("text-xs font-mono font-bold px-2 py-1 rounded bg-white/5", 
                    result.sslScore > 50 ? "text-red-400" : "text-emerald-400")}>
                    Score: {result.sslScore}
                  </span>
                </div>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {result.sslAnalysis}
                </p>
                <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden">
                  <div 
                    className={cn("h-full transition-all duration-1000", result.sslScore > 50 ? "bg-red-500" : "bg-blue-500")}
                    style={{ width: `${result.sslScore}%` }}
                  />
                </div>
              </div>

              <div className="bg-[#141414] border border-white/5 p-6 rounded-xl space-y-4 relative overflow-hidden">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-purple-500">
                    <Activity className="w-5 h-5" />
                    <h4 className="font-bold">Behavioral</h4>
                  </div>
                  <span className={cn("text-xs font-mono font-bold px-2 py-1 rounded bg-white/5", 
                    result.behaviorScore > 50 ? "text-red-400" : "text-emerald-400")}>
                    Score: {result.behaviorScore}
                  </span>
                </div>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {result.behaviorAnalysis}
                </p>
                <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden">
                  <div 
                    className={cn("h-full transition-all duration-1000", result.behaviorScore > 50 ? "bg-red-500" : "bg-purple-500")}
                    style={{ width: `${result.behaviorScore}%` }}
                  />
                </div>
                <div className="pt-2 flex items-center gap-2">
                  <span className="text-[10px] font-bold uppercase tracking-widest text-gray-500">Domain Age:</span>
                  <span className="text-xs font-mono text-emerald-500">{result.domainAge}</span>
                </div>
              </div>
            </div>

            {/* Recommendations */}
            <div className="bg-[#141414] border border-white/5 p-8 rounded-2xl space-y-6">
              <h4 className="text-xl font-bold flex items-center gap-2">
                <Info className="w-5 h-5 text-emerald-500" />
                Security Recommendations
              </h4>
              <ul className="space-y-4">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex gap-4 items-start">
                    <div className="mt-1.5 w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
                    <span className="text-gray-300">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </motion.div>
        ) : isAnalyzing ? (
          <div className="space-y-8">
            <div className="bg-[#141414] border border-white/5 p-12 rounded-2xl flex flex-col items-center justify-center text-center space-y-8 relative overflow-hidden">
              {/* Animated Background Pulse */}
              <motion.div 
                animate={{ 
                  scale: [1, 1.2, 1],
                  opacity: [0.1, 0.2, 0.1]
                }}
                transition={{ duration: 4, repeat: Infinity }}
                className="absolute inset-0 bg-emerald-500/10 blur-3xl rounded-full"
              />

              <div className="relative">
                <div className="w-24 h-24 border-4 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin" />
                <div className="absolute inset-0 flex items-center justify-center">
                  <Shield className="w-8 h-8 text-emerald-500 animate-pulse" />
                </div>
              </div>

              <div className="space-y-4 relative z-10">
                <h3 className="text-2xl font-bold tracking-tight">Deep Scan in Progress</h3>
                <div className="flex flex-col items-center gap-2">
                  {steps.map((step, idx) => (
                    <motion.div 
                      key={idx}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ 
                        opacity: idx === analysisStep ? 1 : idx < analysisStep ? 0.5 : 0.2,
                        x: 0,
                        scale: idx === analysisStep ? 1.05 : 1
                      }}
                      className={cn(
                        "flex items-center gap-3 text-sm font-medium transition-all",
                        idx === analysisStep ? "text-emerald-400" : "text-gray-500"
                      )}
                    >
                      {idx < analysisStep ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-500" />
                      ) : idx === analysisStep ? (
                        <div className="w-4 h-4 border-2 border-emerald-500/30 border-t-emerald-500 rounded-full animate-spin" />
                      ) : (
                        <div className="w-4 h-4 border-2 border-white/10 rounded-full" />
                      )}
                      {step}
                    </motion.div>
                  ))}
                </div>
              </div>

              <div className="w-full max-w-md h-1 bg-white/5 rounded-full overflow-hidden">
                <motion.div 
                  className="h-full bg-emerald-500"
                  initial={{ width: "0%" }}
                  animate={{ width: `${((analysisStep + 1) / steps.length) * 100}%` }}
                />
              </div>
            </div>

            <div className="grid grid-cols-3 gap-6 opacity-20">
              <div className="h-40 bg-white/5 rounded-xl border border-white/10" />
              <div className="h-40 bg-white/5 rounded-xl border border-white/10" />
              <div className="h-40 bg-white/5 rounded-xl border border-white/10" />
            </div>
          </div>
        ) : (
          <div className="h-96 flex flex-col items-center justify-center text-center space-y-4 border border-dashed border-white/10 rounded-2xl bg-white/[0.02]">
            <div className="w-16 h-16 bg-white/5 rounded-full flex items-center justify-center">
              <Shield className="w-8 h-8 text-gray-600" />
            </div>
            <div>
              <h3 className="text-lg font-bold">Ready to Scan</h3>
              <p className="text-gray-500 max-w-xs mx-auto">
                Enter a URL above to begin the deep analysis process.
              </p>
            </div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
