import React, { useState, useEffect, createContext, useContext } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from "react-router-dom";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState(localStorage.getItem('token'));

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchUserInfo();
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchUserInfo = async () => {
    try {
      const response = await axios.get(`${API}/auth/me`);
      setUser(response.data);
    } catch (error) {
      console.error('Failed to fetch user info:', error);
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = (token, userData) => {
    localStorage.setItem('token', token);
    setToken(token);
    setUser(userData);
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    delete axios.defaults.headers.common['Authorization'];
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Protected Route Component
const ProtectedRoute = ({ children, adminOnly = false }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (adminOnly && user.role !== 'admin') {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

// Login Component
const Login = () => {
  const [step, setStep] = useState('login'); // 'login' or 'mfa'
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    mfaCode: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post(`${API}/auth/login`, {
        username: formData.username,
        password: formData.password
      });

      if (response.data.requires_mfa) {
        setStep('mfa');
      }
    } catch (error) {
      setError(error.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleMFA = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post(`${API}/auth/verify-mfa`, {
        username: formData.username,
        mfa_code: formData.mfaCode
      });

      login(response.data.access_token, response.data.user);
      navigate('/dashboard');
    } catch (error) {
      setError(error.response?.data?.detail || 'MFA verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900 px-4">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <div className="mx-auto h-12 w-12 bg-blue-600 rounded-lg flex items-center justify-center mb-4">
            <svg className="h-8 w-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-white">ZTNA Security Portal</h2>
          <p className="mt-2 text-gray-300">
            {step === 'login' ? 'Sign in to your account' : 'Enter your MFA code'}
          </p>
        </div>

        <div className="bg-gray-800 py-8 px-6 rounded-xl shadow-2xl">
          {error && (
            <div className="mb-4 bg-red-900 border border-red-700 text-red-100 px-4 py-3 rounded">
              {error}
            </div>
          )}

          {step === 'login' ? (
            <form onSubmit={handleLogin} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Username
                </label>
                <input
                  type="text"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  required
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Enter your username"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Password
                </label>
                <input
                  type="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  required
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Enter your password"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Signing in...' : 'Sign in'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleMFA} className="space-y-6">
              <div className="text-center">
                <p className="text-gray-300 mb-4">
                  We've sent a verification code to your email. Please enter it below.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  MFA Code
                </label>
                <input
                  type="text"
                  name="mfaCode"
                  value={formData.mfaCode}
                  onChange={handleChange}
                  required
                  maxLength={6}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-lg tracking-widest"
                  placeholder="000000"
                />
              </div>

              <div className="flex space-x-3">
                <button
                  type="button"
                  onClick={() => setStep('login')}
                  className="flex-1 py-2 px-4 border border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-300 bg-gray-700 hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500"
                >
                  Back
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? 'Verifying...' : 'Verify'}
                </button>
              </div>
            </form>
          )}

          <div className="mt-6 text-center">
            <p className="text-xs text-gray-400">
              Default admin credentials: <strong>admin / admin123</strong>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = () => {
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    fetchApplications();
  }, []);

  const fetchApplications = async () => {
    try {
      const response = await axios.get(`${API}/applications`);
      setApplications(response.data);
    } catch (error) {
      console.error('Failed to fetch applications:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAccessApplication = async (appId) => {
    try {
      const response = await axios.post(`${API}/applications/${appId}/access`);
      // Open application in new tab
      window.open(response.data.redirect_url, '_blank');
    } catch (error) {
      alert(error.response?.data?.detail || 'Access denied');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <div className="h-8 w-8 bg-blue-600 rounded-lg flex items-center justify-center mr-3">
                <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h1 className="text-xl font-bold text-white">ZTNA Portal</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-300">Welcome, {user?.username}</span>
              <span className="px-2 py-1 bg-blue-600 text-white text-xs rounded-full">{user?.role}</span>
              {user?.role === 'admin' && (
                <button
                  onClick={() => navigate('/admin')}
                  className="px-4 py-2 bg-gray-700 text-white rounded-md hover:bg-gray-600 transition-colors"
                >
                  Admin Panel
                </button>
              )}
              <button
                onClick={logout}
                className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-white mb-2">Your Applications</h2>
          <p className="text-gray-300">Access your authorized applications securely</p>
        </div>

        {applications.length === 0 ? (
          <div className="text-center py-12">
            <div className="mx-auto h-12 w-12 bg-gray-700 rounded-lg flex items-center justify-center mb-4">
              <svg className="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-gray-300 mb-2">No applications available</h3>
            <p className="text-gray-400">Contact your administrator to get access to applications.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {applications.map((app) => (
              <div key={app.id} className="bg-gray-800 rounded-lg shadow-lg hover:shadow-xl transition-shadow">
                <div className="p-6">
                  <div className="flex items-center mb-4">
                    {app.icon_url ? (
                      <img src={app.icon_url} alt={app.name} className="h-10 w-10 rounded-lg mr-3" />
                    ) : (
                      <div className="h-10 w-10 bg-blue-600 rounded-lg flex items-center justify-center mr-3">
                        <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </div>
                    )}
                    <div>
                      <h3 className="text-lg font-semibold text-white">{app.name}</h3>
                      <span className="text-xs text-gray-400 bg-gray-700 px-2 py-1 rounded">{app.category}</span>
                    </div>
                  </div>
                  <p className="text-gray-300 text-sm mb-4">{app.description}</p>
                  <button
                    onClick={() => handleAccessApplication(app.id)}
                    className="w-full px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors flex items-center justify-center"
                  >
                    <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                    Access Application
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
};

// Admin Panel Component
const AdminPanel = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [stats, setStats] = useState({});
  const [applications, setApplications] = useState([]);
  const [users, setUsers] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [statsRes, appsRes, usersRes, policiesRes, logsRes] = await Promise.all([
        axios.get(`${API}/admin/stats`),
        axios.get(`${API}/admin/applications`),
        axios.get(`${API}/admin/users`),
        axios.get(`${API}/admin/policies`),
        axios.get(`${API}/admin/logs`)
      ]);

      setStats(statsRes.data);
      setApplications(appsRes.data);
      setUsers(usersRes.data);
      setPolicies(policiesRes.data);
      setLogs(logsRes.data);
    } catch (error) {
      console.error('Failed to fetch admin data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  const tabs = [
    { id: 'dashboard', name: 'Dashboard', icon: 'M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z' },
    { id: 'applications', name: 'Applications', icon: 'M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10' },
    { id: 'users', name: 'Users', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z' },
    { id: 'policies', name: 'Policies', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
    { id: 'logs', name: 'Access Logs', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' }
  ];

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <div className="h-8 w-8 bg-red-600 rounded-lg flex items-center justify-center mr-3">
                <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
              </div>
              <h1 className="text-xl font-bold text-white">ZTNA Admin Panel</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-300">Welcome, {user?.username}</span>
              <button
                onClick={() => navigate('/dashboard')}
                className="px-4 py-2 bg-gray-700 text-white rounded-md hover:bg-gray-600 transition-colors"
              >
                User Portal
              </button>
              <button
                onClick={logout}
                className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <nav className="bg-gray-800 w-64 min-h-screen pt-8">
          <div className="px-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center px-4 py-3 text-left rounded-lg mb-2 transition-colors ${
                  activeTab === tab.id
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                }`}
              >
                <svg className="h-5 w-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
                </svg>
                {tab.name}
              </button>
            ))}
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-8">
          {activeTab === 'dashboard' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">Dashboard Overview</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div className="bg-gray-800 p-6 rounded-lg">
                  <div className="flex items-center">
                    <div className="p-2 bg-blue-600 rounded-lg">
                      <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                      </svg>
                    </div>
                    <div className="ml-4">
                      <p className="text-sm font-medium text-gray-400">Total Users</p>
                      <p className="text-2xl font-bold text-white">{stats.total_users || 0}</p>
                    </div>
                  </div>
                </div>
                <div className="bg-gray-800 p-6 rounded-lg">
                  <div className="flex items-center">
                    <div className="p-2 bg-green-600 rounded-lg">
                      <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                      </svg>
                    </div>
                    <div className="ml-4">
                      <p className="text-sm font-medium text-gray-400">Applications</p>
                      <p className="text-2xl font-bold text-white">{stats.total_applications || 0}</p>
                    </div>
                  </div>
                </div>
                <div className="bg-gray-800 p-6 rounded-lg">
                  <div className="flex items-center">
                    <div className="p-2 bg-purple-600 rounded-lg">
                      <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                    </div>
                    <div className="ml-4">
                      <p className="text-sm font-medium text-gray-400">Policies</p>
                      <p className="text-2xl font-bold text-white">{stats.total_policies || 0}</p>
                    </div>
                  </div>
                </div>
                <div className="bg-gray-800 p-6 rounded-lg">
                  <div className="flex items-center">
                    <div className="p-2 bg-orange-600 rounded-lg">
                      <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                      </svg>
                    </div>
                    <div className="ml-4">
                      <p className="text-sm font-medium text-gray-400">Active Users</p>
                      <p className="text-2xl font-bold text-white">{stats.active_users || 0}</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-gray-800 rounded-lg p-6">
                <h3 className="text-lg font-bold text-white mb-4">Recent Access Attempts</h3>
                <div className="overflow-x-auto">
                  <table className="min-w-full">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left py-3 px-4 text-gray-300">User</th>
                        <th className="text-left py-3 px-4 text-gray-300">Application</th>
                        <th className="text-left py-3 px-4 text-gray-300">Action</th>
                        <th className="text-left py-3 px-4 text-gray-300">Status</th>
                        <th className="text-left py-3 px-4 text-gray-300">Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {stats.recent_access_attempts?.slice(0, 5).map((log) => (
                        <tr key={log.id} className="border-b border-gray-800">
                          <td className="py-3 px-4 text-gray-300">{log.username}</td>
                          <td className="py-3 px-4 text-gray-300">{log.application_name}</td>
                          <td className="py-3 px-4 text-gray-300">{log.action}</td>
                          <td className="py-3 px-4">
                            <span className={`px-2 py-1 rounded-full text-xs ${
                              log.success ? 'bg-green-900 text-green-100' : 'bg-red-900 text-red-100'
                            }`}>
                              {log.success ? 'Success' : 'Failed'}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-gray-300">
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'applications' && (
            <div>
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-bold text-white">Applications</h2>
                <button className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                  Add Application
                </button>
              </div>
              <div className="bg-gray-800 rounded-lg overflow-hidden">
                <table className="min-w-full">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="text-left py-3 px-4 text-gray-300">Name</th>
                      <th className="text-left py-3 px-4 text-gray-300">URL</th>
                      <th className="text-left py-3 px-4 text-gray-300">Category</th>
                      <th className="text-left py-3 px-4 text-gray-300">Status</th>
                      <th className="text-left py-3 px-4 text-gray-300">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {applications.map((app) => (
                      <tr key={app.id} className="border-b border-gray-700">
                        <td className="py-3 px-4 text-white font-medium">{app.name}</td>
                        <td className="py-3 px-4 text-gray-300">{app.url}</td>
                        <td className="py-3 px-4 text-gray-300">{app.category}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 rounded-full text-xs ${
                            app.is_active ? 'bg-green-900 text-green-100' : 'bg-red-900 text-red-100'
                          }`}>
                            {app.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <button className="text-blue-400 hover:text-blue-300 mr-3">Edit</button>
                          <button className="text-red-400 hover:text-red-300">Delete</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'users' && (
            <div>
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-bold text-white">Users</h2>
                <button className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                  Add User
                </button>
              </div>
              <div className="bg-gray-800 rounded-lg overflow-hidden">
                <table className="min-w-full">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="text-left py-3 px-4 text-gray-300">Username</th>
                      <th className="text-left py-3 px-4 text-gray-300">Email</th>
                      <th className="text-left py-3 px-4 text-gray-300">Role</th>
                      <th className="text-left py-3 px-4 text-gray-300">Status</th>
                      <th className="text-left py-3 px-4 text-gray-300">Last Login</th>
                      <th className="text-left py-3 px-4 text-gray-300">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((user) => (
                      <tr key={user.id} className="border-b border-gray-700">
                        <td className="py-3 px-4 text-white font-medium">{user.username}</td>
                        <td className="py-3 px-4 text-gray-300">{user.email}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 rounded-full text-xs ${
                            user.role === 'admin' ? 'bg-red-900 text-red-100' : 
                            user.role === 'user' ? 'bg-blue-900 text-blue-100' : 'bg-gray-900 text-gray-100'
                          }`}>
                            {user.role}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 rounded-full text-xs ${
                            user.is_active ? 'bg-green-900 text-green-100' : 'bg-red-900 text-red-100'
                          }`}>
                            {user.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-300">
                          {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
                        </td>
                        <td className="py-3 px-4">
                          <button className="text-blue-400 hover:text-blue-300 mr-3">Edit</button>
                          <button className="text-red-400 hover:text-red-300">Delete</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'policies' && (
            <div>
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-bold text-white">Access Policies</h2>
                <button className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                  Create Policy
                </button>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {policies.map((policy) => (
                  <div key={policy.id} className="bg-gray-800 rounded-lg p-6">
                    <div className="flex justify-between items-start mb-4">
                      <h3 className="text-lg font-semibold text-white">{policy.name}</h3>
                      <span className={`px-2 py-1 rounded-full text-xs ${
                        policy.is_active ? 'bg-green-900 text-green-100' : 'bg-red-900 text-red-100'
                      }`}>
                        {policy.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </div>
                    <p className="text-gray-300 text-sm mb-4">{policy.description}</p>
                    <div className="space-y-2">
                      <div>
                        <span className="text-gray-400 text-xs">Roles:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {policy.user_roles.map((role) => (
                            <span key={role} className="px-2 py-1 bg-blue-900 text-blue-100 text-xs rounded">
                              {role}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <span className="text-gray-400 text-xs">Applications:</span>
                        <p className="text-gray-300 text-sm">{policy.applications.length} applications</p>
                      </div>
                    </div>
                    <div className="flex justify-end space-x-2 mt-4">
                      <button className="text-blue-400 hover:text-blue-300 text-sm">Edit</button>
                      <button className="text-red-400 hover:text-red-300 text-sm">Delete</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">Access Logs</h2>
              <div className="bg-gray-800 rounded-lg overflow-hidden">
                <table className="min-w-full">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="text-left py-3 px-4 text-gray-300">Time</th>
                      <th className="text-left py-3 px-4 text-gray-300">User</th>
                      <th className="text-left py-3 px-4 text-gray-300">Application</th>
                      <th className="text-left py-3 px-4 text-gray-300">Action</th>
                      <th className="text-left py-3 px-4 text-gray-300">IP Address</th>
                      <th className="text-left py-3 px-4 text-gray-300">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.slice(0, 20).map((log) => (
                      <tr key={log.id} className="border-b border-gray-700">
                        <td className="py-3 px-4 text-gray-300 text-sm">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 text-white">{log.username}</td>
                        <td className="py-3 px-4 text-gray-300">{log.application_name}</td>
                        <td className="py-3 px-4 text-gray-300">{log.action}</td>
                        <td className="py-3 px-4 text-gray-300">{log.ip_address}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 rounded-full text-xs ${
                            log.success ? 'bg-green-900 text-green-100' : 'bg-red-900 text-red-100'
                          }`}>
                            {log.success ? 'Success' : 'Failed'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

// Main App Component
function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/dashboard" element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } />
            <Route path="/admin" element={
              <ProtectedRoute adminOnly={true}>
                <AdminPanel />
              </ProtectedRoute>
            } />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </div>
  );
}

export default App;