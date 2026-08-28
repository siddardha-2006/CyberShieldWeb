/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Exact 6-color palette from download (4).jpg
        pine: {
          900: "#051F20", // #051F20 - Base Dark Obsidian Pine
          800: "#0B2B26", // #0B2B26 - Deep Forest Pine
          700: "#163832", // #163832 - Rich Pine Card Background
          600: "#235347", // #235347 - Medium Emerald / Borders
          300: "#8EB69B", // #8EB69B - Soft Sage Mint / Accents
          100: "#DAF1DE", // #DAF1DE - Pale Ice Mint / Highlights & Text
        },
        cyber: {
          bg: "#051F20",
          dark: "#0B2B26",
          card: "#163832",
          cardborder: "#235347",
          teal: "#235347",
          teallight: "#8EB69B",
          sand: "#8EB69B",
          peach: "#8EB69B",
          ice: "#DAF1DE",
          danger: "#e63946",
          warn: "#e9c46a",
          safe: "#52b788",
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Menlo', 'Consolas', 'monospace'],
        sans: ['"Space Grotesk"', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'glow-mint': '0 0 25px -5px rgba(142, 182, 155, 0.4)',
        'glow-emerald': '0 0 30px -5px rgba(35, 83, 71, 0.6)',
        'glow-ice': '0 0 35px -5px rgba(218, 241, 222, 0.3)',
      }
    },
  },
  plugins: [],
}
