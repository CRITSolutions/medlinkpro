import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    include: [
      'src/**/*.{test,spec}.{js,jsx,ts,tsx}',
      'src/__tests__/**/*.{js,jsx,ts,tsx}'
    ]
  },
})
