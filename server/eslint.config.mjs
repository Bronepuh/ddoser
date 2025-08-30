// eslint.config.mjs
import js from '@eslint/js';
import globals from 'globals';
import tsplugin from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import prettier from 'eslint-plugin-prettier/recommended';

export default tsplugin.config(
  {
    ignores: ['dist', 'node_modules'],
    languageOptions: {
      parser: '@typescript-eslint/parser',
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: new URL('.', import.meta.url).pathname,
        ecmaVersion: 2020,
        sourceType: 'module',
      },
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.jest,
      },
    },
  },
  js.configs.recommended, // базовый JS lint
  ...tsplugin.configs.recommendedTypeChecked, // проверка TS типов
  reactHooks.configs['recommended-latest'], // хуки React
  prettier,
  {
    rules: {
      // запрет any
      '@typescript-eslint/no-explicit-any': 'error',
      // предупреждение про промисы без await
      '@typescript-eslint/no-floating-promises': 'warn',
      // предупреждение про незащищенные аргументы
      '@typescript-eslint/no-unsafe-argument': 'warn',
      '@typescript-eslint/no-unsafe-assignment': 'warn',
      '@typescript-eslint/no-unsafe-member-access': 'warn',
      '@typescript-eslint/no-unsafe-call': 'warn',
    },
  }
);
