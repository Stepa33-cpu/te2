const API_URL = 'https://dashboard.lexchain.net';
const FRONTEND_URL = 'https://dashboard.lexchain.net';

export const authService = {
    checkAuth: async () => {
        try {
            const response = await fetch(`${API_URL}/api/user`, {
                credentials: 'include'
            });
            if (!response.ok) throw new Error('Not authenticated');
            return await response.json();
        } catch (error) {
            throw error;
        }
    },

    logout: async () => {
        try {
            await fetch(`${API_URL}/api/logout`, {
                credentials: 'include'
            });
            window.location.href = `${FRONTEND_URL}/login`;
        } catch (error) {
            console.error('Logout error:', error);
        }
    },

    loginWithMicrosoft: () => {
        window.location.href = `${API_URL}/login`;
    }
}; 