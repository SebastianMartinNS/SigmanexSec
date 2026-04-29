/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: ['./index.html'],
  theme: {
    extend: {
      colors: {
        ink:    { 900: '#0a0e14', 800: '#11161d', 700: '#1a2029', 600: '#252d3a' },
        accent: { 400: '#7dd3fc', 500: '#38bdf8', 600: '#0ea5e9' },
        warn:   { 500: '#f59e0b' },
        danger: { 500: '#ef4444' },
        ok:     { 500: '#10b981' },
      },
    },
  },
  plugins: [],
};
