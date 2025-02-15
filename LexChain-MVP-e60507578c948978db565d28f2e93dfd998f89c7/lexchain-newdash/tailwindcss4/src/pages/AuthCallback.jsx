import { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const AuthCallback = () => {
    const [error, setError] = useState(null);
    const navigate = useNavigate();
    const location = useLocation();

    useEffect(() => {
        const handleCallback = async () => {
            try {
                // Get code from URL
                const params = new URLSearchParams(location.search);
                const code = params.get('code');
                const state = params.get('state');
                
                // Verify state
                const savedState = sessionStorage.getItem('auth_state');
                if (state !== savedState) {
                    throw new Error('State verification failed');
                }
                
                // Clear stored state
                sessionStorage.removeItem('auth_state');

                if (!code) {
                    throw new Error('No authorization code received');
                }

                // Exchange code for token
                const response = await fetch('http://localhost:5000/auth/token', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ code })
                });

                if (!response.ok) {
                    const data = await response.json();
                    throw new Error(data.error || 'Token exchange failed');
                }

                // Redirect to dashboard
                navigate('/');
            } catch (error) {
                console.error('Authentication error:', error);
                setError(error.message);
            }
        };

        handleCallback();
    }, [navigate, location]);

    if (error) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-100">
                <div className="bg-white p-8 rounded-lg shadow-md">
                    <h2 className="text-red-600 text-xl font-semibold mb-4">Authentication Error</h2>
                    <p className="text-gray-600">{error}</p>
                    <button
                        onClick={() => navigate('/login')}
                        className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                    >
                        Return to Login
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-100">
            <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-600 border-t-transparent mx-auto"></div>
                <p className="mt-4 text-gray-600">Completing sign in...</p>
            </div>
        </div>
    );
};

export default AuthCallback; 