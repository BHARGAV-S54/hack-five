import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, History, Settings, LogOut, User } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

export default function Navbar() {
  const { user, logout } = useAuth();
  const location = useLocation();

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'History', path: '/history', icon: History },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <nav className="fixed top-0 left-0 bottom-0 w-64 bg-black/50 backdrop-blur-xl border-r border-white/5 z-50 flex flex-col p-6">
      <Link to="/" className="flex items-center gap-3 group mb-12">
        <div className="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center shadow-[0_0_20px_rgba(16,185,129,0.3)] group-hover:scale-110 transition-transform">
          <Shield className="w-5 h-5 text-black" />
        </div>
        <span className="font-bold tracking-tight text-lg leading-tight">Risk <span className="text-emerald-500">Analyzer</span></span>
      </Link>

      <div className="flex-1 flex flex-col gap-2">
        <div className="text-[10px] font-bold uppercase tracking-widest text-gray-500 mb-2 px-4">Main Menu</div>
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={cn(
              "px-4 py-3 rounded-xl text-sm font-medium transition-all flex items-center gap-3",
              location.pathname === item.path 
                ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20" 
                : "text-gray-400 hover:text-white hover:bg-white/5 border border-transparent"
            )}
          >
            <item.icon className="w-5 h-5" />
            {item.name}
          </Link>
        ))}
      </div>

      <div className="mt-auto pt-6 border-t border-white/5">
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-white/5 border border-white/5">
          <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center">
            <User className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-xs font-bold text-gray-200 truncate">{user?.name || 'Guest'}</span>
            <span className="text-[10px] text-gray-500 truncate">{user?.email || 'guest@example.com'}</span>
          </div>
        </div>
      </div>
    </nav>
  );
}
