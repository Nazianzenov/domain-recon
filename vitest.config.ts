import { defineConfig } from 'vitest/config';
import { WxtVitest } from 'wxt/testing/vitest-plugin';

export default defineConfig({
  // WxtVitest wires up the @/ aliases and an in-memory fake `browser`.
  plugins: [WxtVitest()],
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    restoreMocks: true,
  },
});
