const iden3Config = require('@iden3/eslint-config');
const { spellcheckerRule, cspellConfig } = require('@iden3/eslint-config/cspell');

module.exports = {
  ...iden3Config,
  rules: {
    '@cspell/spellchecker': [
      1,
      {
        ...spellcheckerRule,
        cspell: {
          ...cspellConfig,
          ignoreWords: ['unmarshal', 'UWLEWdAWcosiLkYoL0KWwZpgEOrPPepl6T5gC', 'mesage']
        }
      }
    ]
  }
};
