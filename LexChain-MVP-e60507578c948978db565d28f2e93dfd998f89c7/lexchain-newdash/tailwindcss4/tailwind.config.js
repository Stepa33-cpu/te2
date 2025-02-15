/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}", // Include toate fișierele relevante
    ],
    theme: {
        extend: {
            animation: {
                'gradient-x': 'gradient-x 15s ease infinite',
                'float-slow': 'float 20s ease-in-out infinite',
                'float-medium': 'float 15s ease-in-out infinite',
                'float-fast': 'float 10s ease-in-out infinite',
                'pulse-slow': 'pulse 10s ease-in-out infinite',
                'pulse-medium': 'pulse 7s ease-in-out infinite',
                'beam-left': 'beam 10s ease-in-out infinite',
                'beam-right': 'beam 15s ease-in-out infinite',
            },
            keyframes: {
                'gradient-x': {
                    '0%, 100%': {
                        'background-size': '200% 200%',
                        'background-position': 'left center'
                    },
                    '50%': {
                        'background-size': '200% 200%',
                        'background-position': 'right center'
                    },
                },
                'float': {
                    '0%, 100%': {
                        transform: 'translateY(0)',
                    },
                    '50%': {
                        transform: 'translateY(-20px)',
                    },
                },
                'beam': {
                    '0%, 100%': {
                        opacity: 0.3,
                        transform: 'translateX(0)',
                    },
                    '50%': {
                        opacity: 0.7,
                        transform: 'translateX(10px)',
                    },
                },
            },
        },
    },
    plugins: [],
};
