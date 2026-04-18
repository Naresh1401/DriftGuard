/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        drift: {
          50: '#f0f4ff',
          100: '#dbe4ff',
          200: '#bac8ff',
          300: '#91a7ff',
          400: '#748ffc',
          500: '#5c7cfa',
          600: '#4c6ef5',
          700: '#4263eb',
          800: '#3b5bdb',
          900: '#364fc7',
        },
        severity: {
          1: '#51cf66',
          2: '#fcc419',
          3: '#ff922b',
          4: '#ff6b6b',
          5: '#e03131',
        },
        watch: '#fcc419',
        warning: '#ff922b',
        critical: '#e03131',
      },
    },
  },
  plugins: [],
}
