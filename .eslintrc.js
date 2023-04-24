module.exports = {
  rules: {
    '@typescript-eslint/naming-convention': 0,
    '@typescript-eslint/explicit-module-boundary-types': 0,
    'import/no-extraneous-dependencies': 0,
    'import/no-unresolved': 0,
    'prefer-object-spread': 0,
    '@typescript-eslint/type-annotation-spacing': [
      2,
      {
        // 声明类型时必须无空格
        overrides: {
          colon: {
            before: false,
            after: true,
          },
          arrow: {
            before: true,
            after: true,
          },
        },
      },
    ],
    'import/no-default-export': 0,
    'space-before-function-paren': 0,
  },
  ignorePatterns: ['src/__tests__/**', 'rollup.config.js', 'commitlint.config.js'],
};
