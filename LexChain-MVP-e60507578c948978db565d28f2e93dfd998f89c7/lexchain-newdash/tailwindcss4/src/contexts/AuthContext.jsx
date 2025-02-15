import { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    const login = async () => {
        try {
            const response = await fetch('https://dashboard.lexchain.net/auth/url');
            const data = await response.json();
            
            if (data.url) {
                // Store state for verification
                sessionStorage.setItem('auth_state', data.state);
                // Redirect to Microsoft login
                window.location.href = data.url;
            } else {
                throw new Error('Failed to get authentication URL');
            }
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    };

    const logout = async () => {
        try {
            await fetch('https://dashboard.lexchain.net/auth/logout', {
                method: 'POST',
                credentials: 'include'
            });
            setUser(null);
            navigate('/login');
        } catch (error) {
            console.error('Logout error:', error);
        }
    };

    const checkAuth = async () => {
        try {
            const response = await fetch('https://dashboard.lexchain.net/api/user', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.authenticated) {
                    setUser(data.user);
                } else {
                    setUser(null);
                }
                return data.authenticated;
            }
            return false;
        } catch (error) {
            console.error('Auth check error:', error);
            setUser(null);
            return false;
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        checkAuth();
    }, []);

    return (
        <AuthContext.Provider value={{ user, login, logout, loading }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext); 