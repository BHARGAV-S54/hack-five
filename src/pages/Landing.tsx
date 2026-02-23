import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { BackgroundPaths } from '../components/ui/background-paths';
import PillNav from '../components/PillNav';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Zap, Lock, Eye } from 'lucide-react';

export default function Landing() {
  const navigate = useNavigate();
  const [isAboutOpen, setIsAboutOpen] = useState(false);

  const navItems = [
    { label: 'Home', href: '/' },
    { label: 'Dashboard', href: '/dashboard' },
    { label: 'About', href: '#about' },
    { label: 'Login', href: '/login' },
  ];

  const handleNavClick = (item: any) => {
    if (item.label === 'About') {
      setIsAboutOpen(true);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.5 }}
      className="min-h-screen bg-black dark selection:bg-white/20"
    >
      <PillNav 
        items={navItems} 
        activeHref="/"
        baseColor="#ffffff"
        pillColor="rgba(255, 255, 255, 0.05)"
        onItemClick={handleNavClick}
        onMobileMenuClick={() => {}}
      />
      
      {/* Intercept About click in PillNav - we need to modify PillNav to support custom onClick or just use the href */}
      {/* For now, we'll use a simple overlay if isAboutOpen is true */}

      <BackgroundPaths 
        title="Risk Analyzer" 
        subtitle={`Advanced phishing detection and URL security analysis.\nProtect your digital identity with real-time threat intelligence.`}
        onAction={() => navigate('/login')}
      />

      <AnimatePresence>
        {isAboutOpen && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[200] flex items-center justify-center p-6 backdrop-blur-xl bg-black/60"
          >
            <motion.div 
              initial={{ scale: 0.9, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.9, opacity: 0, y: 20 }}
              className="bg-[#141414] border border-white/10 w-full max-w-2xl rounded-3xl overflow-hidden shadow-2xl"
            >
              <div className="p-8 space-y-8">
                <div className="flex items-center justify-between">
                  <h2 className="text-2xl font-bold tracking-tight text-white">About Risk Analyzer</h2>
                  <button 
                    onClick={() => setIsAboutOpen(false)}
                    className="p-2 hover:bg-white/5 rounded-full transition-colors"
                  >
                    <X className="w-6 h-6 text-gray-500" />
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div className="flex items-start gap-3">
                      <Zap className="w-5 h-5 text-emerald-500 mt-1" />
                      <div>
                        <h4 className="font-bold text-white">Advanced Analysis</h4>
                        <p className="text-sm text-gray-400">Deep heuristic and behavioral analysis of suspicious URLs.</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <Lock className="w-5 h-5 text-blue-500 mt-1" />
                      <div>
                        <h4 className="font-bold text-white">SSL Verification</h4>
                        <p className="text-sm text-gray-400">Automatic certificate validation and security protocol auditing for every scan.</p>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="flex items-start gap-3">
                      <Eye className="w-5 h-5 text-purple-500 mt-1" />
                      <div>
                        <h4 className="font-bold text-white">Threat Detection</h4>
                        <p className="text-sm text-gray-400">Real-time identification of phishing patterns, typosquatting, and malicious redirects.</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <div className="w-5 h-5 mt-1" />
                      <div>
                        <h4 className="font-bold text-white">Security First</h4>
                        <p className="text-sm text-gray-400">Built to empower users with the knowledge to stay safe in an evolving digital landscape.</p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="pt-6 border-t border-white/5">
                  <p className="text-gray-400 text-sm leading-relaxed">
                    Risk Analyzer is a cutting-edge cybersecurity tool designed to protect users from the growing threat of phishing. By combining traditional heuristic checks with advanced analysis models, we provide a comprehensive risk assessment for any URL you encounter.
                  </p>
                </div>

                <button 
                  onClick={() => setIsAboutOpen(false)}
                  className="w-full bg-white text-black font-bold py-4 rounded-2xl hover:bg-gray-200 transition-colors"
                >
                  Got it, thanks!
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
