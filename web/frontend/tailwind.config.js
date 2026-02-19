/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'bz-dark': '#0f172a',
        'bz-darker': '#020617',
        'bz-accent': '#3b82f6',
        'bz-red': '#ef4444',
        'bz-green': '#22c55e',
        'bz-yellow': '#eab308',
      },
    },
  },
  plugins: [],
}
