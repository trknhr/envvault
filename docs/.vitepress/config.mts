import { defineConfig } from 'vitepress'

const githubBase = 'https://github.com/trknhr/envvault/blob/main'

export default defineConfig({
  title: 'EnvVault',
  description: 'Local-first credential launcher with optional localhost proxy.',
  base: '/envvault/',
  outDir: '../site',
  lastUpdated: true,
  ignoreDeadLinks: [/^https:\/\/github\.com\/trknhr\/envvault/],
  themeConfig: {
    logo: {
      light: '/logo.svg',
      dark: '/logo.svg'
    },
    nav: [
      { text: 'Docs', link: '/' },
      { text: 'Examples', link: '/examples' },
      { text: 'GitHub', link: 'https://github.com/trknhr/envvault' }
    ],
    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Quickstart', link: '/quickstart' },
          { text: 'Proxies', link: '/proxies' }
        ]
      },
      {
        text: 'Credential Flows',
        items: [
          { text: 'Examples', link: '/examples' },
          { text: 'Gemini AI SDK Proxy', link: '/examples/gemini-ai-sdk-proxy-app' },
          { text: 'OpenAI Proxy', link: '/examples/openai-proxy-app' }
        ]
      },
      {
        text: 'Operations',
        items: [
          { text: 'Recovery', link: '/recovery' },
          { text: 'Uninstall', link: '/uninstall' }
        ]
      },
      {
        text: 'Reference',
        items: [
          { text: 'Threat Model', link: '/threat-model' },
          { text: 'Third-Party Notices', link: '/third-party-notices' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/trknhr/envvault' }
    ],
    search: {
      provider: 'local'
    },
    editLink: {
      pattern: `${githubBase}/docs/:path`,
      text: 'Edit this page on GitHub'
    },
    footer: {
      message: 'Local-first credentials for development workflows.'
    }
  },
  head: [
    ['link', { rel: 'icon', href: '/envvault/logo.svg' }]
  ]
})
