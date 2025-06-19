import React, { useState, useContext, createContext, useEffect } from 'react';
import { AlertCircle, Eye, EyeOff, LogOut, User, Shield, Settings, Users } from 'lucide-react';

// Auth Context
const AuthContext = createContext(null);

// API Configuration - Updated for your backend port
const API_BASE = 'http://localhost:3001/api/v1';

// Auth Service
class AuthService {
  static async login(email, password) {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email, password })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Login failed');
    }
    
    return response.json();
  }

  static async logout() {
    const response = await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      credentials: 'include'
    });
    return response.ok;
  }

  static async getProfile() {
    const response = await fetch(`${API_BASE}/auth/profile`, {
      credentials: 'include'
    });
    
    if (!response.ok) throw new Error('Failed to get profile');
    return response.json();
  }

  static async refreshToken() {
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      credentials: 'include'
    });
    
    if (!response.ok) throw new Error('Failed to refresh token');
    return response.json();
  }
}

// Role-based access utilities
const ROLE_HIERARCHY = {
  super_admin: 4,
  billing_manager: 3,
  billing_specialist: 2,
  provider: 1
};

const hasPermission = (userRole, requiredRole) => {
  return ROLE_HIERARCHY[userRole] >= ROLE_HIERARCHY[requiredRole];
};

// Auth Provider Component
function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const response = await AuthService.getProfile();
      setUser(response.data.user);
    } catch (err) {
      console.log('Not authenticated');
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    try {
      setError(null);
      const response = await AuthService.login(email, password);
      setUser(response.data.user);
      return { success: true };
    } catch (err) {
      setError(err.message);
      return { success: false, error: err.message };
    }
  };

  const logout = async () => {
    try {
      await AuthService.logout();
      setUser(null);
    } catch (err) {
      console.error('Logout error:', err);
    }
  };

  const value = {
    user,
    login,
    logout,
    loading,
    error,
    isAuthenticated: !!user,
    hasPermission: (role) => user ? hasPermission(user.role, role) : false
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// Custom hook to use auth context
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// Protected Route Component
function ProtectedRoute({ children, requiredRole = null }) {
  const { user, loading, hasPermission } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!user) {
    return <LoginForm />;
  }

  if (requiredRole && !hasPermission(requiredRole)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <Shield className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">Access Denied</h3>
          <p className="mt-1 text-sm text-gray-500">
            You don't have permission to access this resource.
          </p>
        </div>
      </div>
    );
  }

  return children;
}

// Login Form Component
function LoginForm() {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const { login, error } = useAuth();

  // Demo user credentials for easy testing
  const demoUsers = [
    { email: 'admin@medlinkpro.demo', role: 'Super Admin', color: 'bg-purple-100 text-purple-800' },
    { email: 'billing.manager@medlinkpro.demo', role: 'Billing Manager', color: 'bg-blue-100 text-blue-800' },
    { email: 'specialist@medlinkpro.demo', role: 'Billing Specialist', color: 'bg-green-100 text-green-800' },
    { email: 'provider@medlinkpro.demo', role: 'Provider', color: 'bg-orange-100 text-orange-800' }
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    
    const result = await login(formData.email, formData.password);
    setIsLoading(false);
  };

  const fillDemoUser = (email) => {
    setFormData({ email, password: 'Admin123!' });
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="mx-auto h-12 w-12 bg-blue-600 rounded-lg flex items-center justify-center">
            <Shield className="h-8 w-8 text-white" />
          </div>
          <h2 className="mt-6 text-center text-3xl font-bold text-gray-900">
            MedLinkPro
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            HIPAA-Compliant Medical Billing Platform
          </p>
        </div>

        {/* Demo Users Quick Access */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="text-sm font-medium text-blue-900 mb-2">Demo Users (Password: Admin123!)</h3>
          <div className="grid grid-cols-2 gap-2">
            {demoUsers.map((user) => (
              <button
                key={user.email}
                onClick={() => fillDemoUser(user.email)}
                className="text-left p-2 rounded text-xs bg-white hover:bg-gray-50 border"
              >
                <div className="font-medium text-gray-900">{user.email.split('@')[0]}</div>
                <div className={`inline-block px-2 py-1 rounded-full text-xs ${user.color}`}>
                  {user.role}
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="mt-8 space-y-6">
          {error && (
            <div className="rounded-md bg-red-50 p-4">
              <div className="flex">
                <AlertCircle className="h-5 w-5 text-red-400" />
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">
                    Authentication Error
                  </h3>
                  <div className="mt-2 text-sm text-red-700">{error}</div>
                </div>
              </div>
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                Email Address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                placeholder="Enter your email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <div className="mt-1 relative">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  required
                  className="appearance-none relative block w-full px-3 py-2 pr-10 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                  placeholder="Enter your password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4 text-gray-400" />
                  ) : (
                    <Eye className="h-4 w-4 text-gray-400" />
                  )}
                </button>
              </div>
            </div>
          </div>

          <div>
            <button
              onClick={handleSubmit}
              disabled={isLoading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-lg text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              ) : (
                'Sign In'
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// Dashboard Component
function Dashboard() {
  const { user, logout, hasPermission } = useAuth();

  const getRoleColor = (role) => {
    const colors = {
      super_admin: 'bg-purple-100 text-purple-800',
      billing_manager: 'bg-blue-100 text-blue-800',
      billing_specialist: 'bg-green-100 text-green-800',
      provider: 'bg-orange-100 text-orange-800'
    };
    return colors[role] || 'bg-gray-100 text-gray-800';
  };

  const getRoleLabel = (role) => {
    const labels = {
      super_admin: 'Super Admin',
      billing_manager: 'Billing Manager',
      billing_specialist: 'Billing Specialist',
      provider: 'Provider'
    };
    return labels[role] || role;
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <h1 className="text-2xl font-bold text-gray-900">MedLinkPro</h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-3">
                <User className="h-5 w-5 text-gray-400" />
                <div className="text-sm">
                  <div className="font-medium text-gray-900">{user.email}</div>
                  <div className={`inline-block px-2 py-1 rounded-full text-xs ${getRoleColor(user.role)}`}>
                    {getRoleLabel(user.role)}
                  </div>
                </div>
              </div>
              
              <button
                onClick={logout}
                className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <LogOut className="h-4 w-4 mr-2" />
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
            
            {/* User Profile Card */}
            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="p-5">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <User className="h-8 w-8 text-gray-400" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-500 truncate">
                        User Profile
                      </dt>
                      <dd className="text-lg font-medium text-gray-900">
                        {user.isEmailVerified ? 'Verified' : 'Pending Verification'}
                      </dd>
                    </dl>
                  </div>
                </div>
              </div>
              <div className="bg-gray-50 px-5 py-3">
                <div className="text-sm">
                  <div className="text-gray-500">Email: {user.email}</div>
                  <div className="text-gray-500">Status: {user.status}</div>
                  <div className="text-gray-500">
                    HIPAA Training: {user.hipaaTrainingCompleted ? '✅ Complete' : '❌ Required'}
                  </div>
                </div>
              </div>
            </div>

            {/* Role-based Access Demo */}
            {hasPermission('billing_specialist') && (
              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <Settings className="h-8 w-8 text-green-400" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Billing Access
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          Available
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
                <div className="bg-gray-50 px-5 py-3">
                  <div className="text-sm text-gray-500">
                    You can access billing and claims management
                  </div>
                </div>
              </div>
            )}

            {/* Admin Only Content */}
            {hasPermission('billing_manager') && (
              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <Users className="h-8 w-8 text-blue-400" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Management Tools
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          Enabled
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
                <div className="bg-gray-50 px-5 py-3">
                  <div className="text-sm text-gray-500">
                    User management and system administration
                  </div>
                </div>
              </div>
            )}

            {/* Super Admin Only */}
            {hasPermission('super_admin') && (
              <div className="bg-white overflow-hidden shadow rounded-lg border-2 border-purple-200">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <Shield className="h-8 w-8 text-purple-500" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Super Admin Panel
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          Full Access
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
                <div className="bg-purple-50 px-5 py-3">
                  <div className="text-sm text-purple-700">
                    Complete system control and configuration
                  </div>
                </div>
              </div>
            )}

          </div>

          {/* Role Permission Demo */}
          <div className="mt-8 bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                Role-Based Access Control Demo
              </h3>
              
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Your Permissions:</h4>
                  <ul className="text-sm text-gray-500 space-y-1">
                    <li>✅ Basic Profile Access</li>
                    {hasPermission('provider') && <li>✅ Provider Dashboard</li>}
                    {hasPermission('billing_specialist') && <li>✅ Billing Operations</li>}
                    {hasPermission('billing_manager') && <li>✅ User Management</li>}
                    {hasPermission('super_admin') && <li>✅ System Administration</li>}
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Role Hierarchy:</h4>
                  <ul className="text-sm text-gray-500 space-y-1">
                    <li>🔹 Provider (Level 1)</li>
                    <li>🔹 Billing Specialist (Level 2)</li>
                    <li>🔹 Billing Manager (Level 3)</li>
                    <li>🔹 Super Admin (Level 4)</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>

        </div>
      </main>
    </div>
  );
}

// Main App Component
export default function App() {
  return (
    <AuthProvider>
      <ProtectedRoute>
        <Dashboard />
      </ProtectedRoute>
    </AuthProvider>
  );
}