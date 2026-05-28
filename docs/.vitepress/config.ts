import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Keylatch',
  description: 'Zero-trust credential vault CLI for AI-assisted workflows',
  themeConfig: {
    nav: [
      { text: 'Getting Started', link: '/getting-started' },
      { text: 'CLI Reference', link: '/cli-reference' },
      { text: 'Provider Templates', link: '/provider-templates' },
    ],
    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Introduction', link: '/' },
          { text: 'Installation & Setup', link: '/getting-started' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'CLI Reference', link: '/cli-reference' },
          { text: 'Provider Templates', link: '/provider-templates' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/keylatch/keylatch' },
    ],
  },
})
