/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: '#0B1D3A',
        teal: '#00C2D4',
        purple: '#6C3FC5',
        critical: '#EF4444',
        high: '#F97316',
        safe: '#22C55E',
      },
    },
  },
  plugins: [],
};
