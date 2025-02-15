import { useAuth } from '../contexts/AuthContext';
import { Link } from 'react-router-dom';
import { Shield, Lock, FileText, Database, Cloud } from 'lucide-react';

const Login = () => {
    const { login } = useAuth();

    const handleLogin = async () => {
        // Redirect to the backend login endpoint
        window.location.href = 'https://dashboard.lexchain.net/login';
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-blue-950 via-blue-900 to-blue-800 flex flex-col justify-center relative overflow-hidden">
            {/* Animated background effects */}
            <div className="absolute inset-0 overflow-hidden">
                {/* Animated gradient background */}
                <div className="absolute inset-0 bg-gradient-to-r from-blue-600/10 via-blue-400/5 to-blue-600/10 animate-gradient-x"></div>
            </div>

            {/* Main content */}
            <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 w-full relative z-10">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-12 items-center">
                    {/* Left side - Features */}
                    <div className="space-y-8 text-white">
                        <div>
                            <h1 className="text-4xl font-bold mb-4">LexChain</h1>
                            <p className="text-xl text-blue-100">
                                Secure, Distributed, and Blockchain-Verified File Storage
                            </p>
                        </div>

                        <div className="space-y-6">
                            <div className="flex items-start space-x-4">
                                <div className="bg-blue-700/30 p-3 rounded-lg">
                                    <Shield className="w-6 h-6" />
                                </div>
                                <div>
                                    <h3 className="font-semibold mb-1">End-to-End Encryption</h3>
                                    <p className="text-blue-100 text-sm">
                                        Your files are encrypted before leaving your device
                                    </p>
                                </div>
                            </div>

                            <div className="flex items-start space-x-4">
                                <div className="bg-blue-700/30 p-3 rounded-lg">
                                    <Database className="w-6 h-6" />
                                </div>
                                <div>
                                    <h3 className="font-semibold mb-1">Blockchain Verification</h3>
                                    <p className="text-blue-100 text-sm">
                                        Every file transaction is recorded and verifiable
                                    </p>
                                </div>
                            </div>

                            <div className="flex items-start space-x-4">
                                <div className="bg-blue-700/30 p-3 rounded-lg">
                                    <Cloud className="w-6 h-6" />
                                </div>
                                <div>
                                    <h3 className="font-semibold mb-1">Distributed Storage</h3>
                                    <p className="text-blue-100 text-sm">
                                        Files are split and stored across multiple secure locations
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Right side - Login */}
                    <div className="bg-white/10 backdrop-blur-lg rounded-2xl shadow-xl p-8 border border-white/20">
                        <div className="text-center mb-8">
                            <h2 className="text-2xl font-bold text-white">Welcome Back</h2>
                            <p className="text-blue-100 mt-2">
                                Sign in to access your secure storage
                            </p>
                        </div>

                        <div className="space-y-6">
                            <button
                                onClick={handleLogin}
                                className="w-full flex items-center justify-center gap-3 px-4 py-3 bg-white/10 hover:bg-white/20 text-white rounded-lg transition-all duration-200 backdrop-blur-lg border border-white/20 hover:border-white/40 shadow-lg"
                            >
                                <Lock className="w-5 h-5" />
                                <span>Sign in with Microsoft</span>
                            </button>

                            <div className="text-center text-sm text-blue-100">
                                <p>
                                    By signing in, you agree to our{' '}
                                    <Link to="/terms" className="text-blue-300 hover:text-blue-200">
                                        Terms of Service
                                    </Link>{' '}
                                    and{' '}
                                    <Link to="/privacy" className="text-blue-300 hover:text-blue-200">
                                        Privacy Policy
                                    </Link>
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Footer */}
            <div className="mt-16 text-center text-blue-200 text-sm relative z-10">
                <p>© 2025 LexChain. All rights reserved.</p>
            </div>
        </div>
    );
};

export default Login; 