import React, { useState, useEffect } from 'react';
import { History as HistoryIcon, Globe, ShieldAlert, ShieldCheck, Trash2, ExternalLink } from 'lucide-react';
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
  timestamp: number;
}

export default function History() {
  const [history, setHistory] = useState<AnalysisResult[]>([]);

  useEffect(() => {
    const saved = localStorage.getItem('phishguard_history');
    if (saved) {
      setHistory(JSON.parse(saved));
    }
  }, []);

  const clearHistory = () => {
    localStorage.removeItem('phishguard_history');
    setHistory([]);
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

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h2 className="text-3xl font-bold tracking-tight text-slate-100">Scan History</h2>
          <p className="text-slate-500">Review your past URL analysis reports.</p>
        </div>
        {history.length > 0 && (
          <button 
            onClick={clearHistory}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-all text-sm font-medium border border-red-500/20"
          >
            <Trash2 className="w-4 h-4" />
            Clear All
          </button>
        )}
      </div>

      <div className="bg-slate-900/50 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-sm">
        <div className="grid grid-cols-12 gap-4 p-4 border-b border-slate-800 text-xs font-bold uppercase tracking-widest text-slate-500">
          <div className="col-span-6">URL / Domain</div>
          <div className="col-span-2 text-center">Risk Score</div>
          <div className="col-span-2 text-center">Level</div>
          <div className="col-span-2 text-right">Date</div>
        </div>

        <div className="divide-y divide-slate-800">
          <AnimatePresence mode="popLayout">
            {history.length > 0 ? (
              history.map((item, i) => (
                <motion.div 
                  key={item.timestamp}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  transition={{ delay: i * 0.05 }}
                  className="grid grid-cols-12 gap-4 p-4 items-center hover:bg-slate-800/50 transition-colors group"
                >
                  <div className="col-span-6 flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center shrink-0 border border-slate-700">
                      <Globe className="w-4 h-4 text-slate-400" />
                    </div>
                    <div className="truncate font-mono text-sm text-slate-300 group-hover:text-slate-100 transition-colors">
                      {item.url}
                    </div>
                  </div>
                  <div className="col-span-2 text-center font-mono font-bold text-slate-200">
                    {item.score}
                  </div>
                  <div className="col-span-2 flex justify-center">
                    <span className={cn(
                      "px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-widest border",
                      item.riskLevel === 'Low' ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-500" :
                      item.riskLevel === 'Medium' ? "bg-amber-500/10 border-amber-500/20 text-amber-500" :
                      item.riskLevel === 'High' ? "bg-orange-500/10 border-orange-500/20 text-orange-500" :
                      "bg-red-500/10 border-red-500/20 text-red-500"
                    )}>
                      {item.riskLevel}
                    </span>
                  </div>
                  <div className="col-span-2 text-right text-xs text-slate-500 font-mono">
                    {new Date(item.timestamp).toLocaleDateString()}
                  </div>
                </motion.div>
              ))
            ) : (
              <div className="p-20 text-center space-y-4">
                <div className="w-16 h-16 bg-slate-900 border border-slate-800 rounded-full flex items-center justify-center mx-auto">
                  <HistoryIcon className="w-8 h-8 text-slate-600" />
                </div>
                <div className="space-y-1">
                  <h3 className="font-bold text-slate-200">No History Found</h3>
                  <p className="text-slate-500 text-sm">Your scan history will appear here once you start analyzing URLs.</p>
                </div>
              </div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
