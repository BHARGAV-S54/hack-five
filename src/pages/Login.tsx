import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Mail, Lock, ArrowRight, Github } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError('Please enter a valid email address.');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }

    const success = login(email, password);
    if (success) {
      navigate('/dashboard');
    } else {
      setError('Invalid email or password. Please check your credentials or create an account.');
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.5 }}
      className="min-h-screen bg-[#0a0a0a] flex items-center justify-center p-6 relative overflow-x-hidden"
    >
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#141414_1px,transparent_1px),linear-gradient(to_bottom,#141414_1px,transparent_1px)] bg-[size:40px_40px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />
      
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md space-y-8 relative"
      >
        <div className="text-center space-y-2">
          <div className="inline-flex w-16 h-16 bg-emerald-500 rounded-2xl items-center justify-center shadow-[0_0_40px_rgba(16,185,129,0.2)] mb-4">
            <Shield className="w-8 h-8 text-black" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-white">Welcome Back</h1>
          <p className="text-gray-500">Secure your digital assets with advanced analysis.</p>
        </div>

        <div className="bg-[#141414] border border-white/5 p-8 rounded-3xl shadow-2xl space-y-6">
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 text-red-500 px-4 py-3 rounded-xl text-sm font-medium">
              {error}
            </div>
          )}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label className="text-xs font-bold uppercase tracking-widest text-gray-500 ml-1">Email Address</label>
              <div className="relative">
                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-600" />
                <input 
                  type="email" 
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@company.com"
                  className="w-full bg-black/50 border border-white/10 rounded-xl py-3 pl-12 pr-4 focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all outline-none text-white"
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-xs font-bold uppercase tracking-widest text-gray-500 ml-1">Password</label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-600" />
                <input 
                  type="password" 
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-black/50 border border-white/10 rounded-xl py-3 pl-12 pr-4 focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all outline-none text-white"
                />
              </div>
            </div>

            <button 
              type="submit"
              className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-4 rounded-xl flex items-center justify-center gap-2 transition-all active:scale-[0.98] group"
            >
              Sign In 
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-gray-500">
          Don't have an account? <Link to="/signup" className="text-emerald-500 font-bold hover:underline">Create one for free</Link>
        </p>
      </motion.div>
    </motion.div>
  );
}
