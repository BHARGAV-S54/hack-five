import React, { useState } from 'react';
import { 
  Settings as SettingsIcon, 
  Bell, 
  Shield, 
  Key, 
  Eye, 
  Moon, 
  Sun, 
  Globe,
  Save,
  CheckCircle2
} from 'lucide-react';
import { motion } from 'framer-motion';

export default function Settings() {
  const [saved, setSaved] = useState(false);
  const [theme, setTheme] = useState('dark');

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const sections = [
    {
      title: 'Security',
      icon: Shield,
      items: [
        { name: 'Two-Factor Auth', desc: 'Add an extra layer of security', value: 'Disabled', type: 'toggle' },
        { name: 'Session Timeout', desc: 'Automatically logout after inactivity', value: '30 Minutes', type: 'select' },
      ]
    },
    {
      title: 'Notifications',
      icon: Bell,
      items: [
        { name: 'Email Alerts', desc: 'Receive reports for critical risks', value: true, type: 'checkbox' },
        { name: 'Browser Push', desc: 'Real-time scan completion alerts', value: false, type: 'checkbox' },
      ]
    }
  ];

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h2 className="text-3xl font-bold tracking-tight text-white">Settings</h2>
          <p className="text-gray-500">Manage your account preferences and security settings.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-8">
        {sections.map((section, idx) => (
          <motion.div 
            key={section.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.1 }}
            className="bg-[#141414] border border-white/5 rounded-2xl overflow-hidden"
          >
            <div className="p-6 border-b border-white/5 flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center">
                <section.icon className="w-5 h-5 text-emerald-500" />
              </div>
              <h3 className="font-bold text-lg text-white">{section.title}</h3>
            </div>
            
            <div className="divide-y divide-white/5">
              {section.items.map((item) => (
                <div key={item.name} className="p-6 flex items-center justify-between hover:bg-white/[0.01] transition-colors">
                  <div className="space-y-1">
                    <div className="font-medium text-gray-200">{item.name}</div>
                    <div className="text-sm text-gray-500">{item.desc}</div>
                  </div>
                  
                  <div className="flex items-center gap-4">
                    {item.type === 'select' && (
                      <select className="bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-gray-300 outline-none focus:border-emerald-500/50">
                        <option>{item.value}</option>
                        <option>Other Option</option>
                      </select>
                    )}
                    {item.type === 'toggle' && (
                      <button className="w-12 h-6 bg-white/5 rounded-full relative p-1 transition-colors hover:bg-white/10">
                        <div className="w-4 h-4 bg-gray-600 rounded-full" />
                      </button>
                    )}
                    {item.type === 'checkbox' && (
                      <input 
                        type="checkbox" 
                        defaultChecked={item.value as boolean}
                        className="w-5 h-5 rounded border-white/10 bg-black/50 text-emerald-500 focus:ring-emerald-500/50"
                      />
                    )}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        ))}

        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-red-500/5 border border-red-500/10 rounded-2xl p-8 space-y-4"
        >
          <h3 className="text-red-500 font-bold flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Danger Zone
          </h3>
          <p className="text-sm text-gray-500 max-w-2xl">
            Deleting your account will permanently remove all your scan history and preferences. This action cannot be undone.
          </p>
          <button className="px-6 py-2 rounded-xl bg-red-500/10 text-red-500 border border-red-500/20 hover:bg-red-500/20 transition-all font-bold text-sm">
            Delete Account
          </button>
        </motion.div>
      </div>
    </div>
  );
}
