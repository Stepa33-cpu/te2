import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export const PrivateRoute = ({ children }) => {
    const { user, loading } = useAuth();

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-950 via-blue-900 to-blue-800">
                <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-300 border-t-transparent"></div>
            </div>
        );
    }

    return user ? children : <Navigate to="/login" />;
}; 