import React, { createContext, useContext, useState, useEffect } from 'react';

interface User {
  email: string;
  name: string;
  password?: string; // Only for storage, not exposed in context user state
}

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => boolean;
  signup: (email: string, name: string, password: string) => boolean;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    const savedUser = localStorage.getItem('phishguard_session');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const signup = (email: string, name: string, password: string): boolean => {
    const usersJson = localStorage.getItem('phishguard_users');
    const users: User[] = usersJson ? JSON.parse(usersJson) : [];
    
    if (users.find(u => u.email === email)) {
      return false; // User already exists
    }

    const newUser = { email, name, password };
    users.push(newUser);
    localStorage.setItem('phishguard_users', JSON.stringify(users));
    
    // Auto login after signup
    const sessionUser = { email, name };
    setUser(sessionUser);
    localStorage.setItem('phishguard_session', JSON.stringify(sessionUser));
    return true;
  };

  const login = (email: string, password: string): boolean => {
    const usersJson = localStorage.getItem('phishguard_users');
    const users: User[] = usersJson ? JSON.parse(usersJson) : [];
    
    const foundUser = users.find(u => u.email === email && u.password === password);
    
    if (foundUser) {
      const sessionUser = { email: foundUser.email, name: foundUser.name };
      setUser(sessionUser);
      localStorage.setItem('phishguard_session', JSON.stringify(sessionUser));
      return true;
    }
    
    return false;
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('phishguard_session');
  };

  return (
    <AuthContext.Provider value={{ user, login, signup, logout, isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
