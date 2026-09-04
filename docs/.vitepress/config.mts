import { defineConfig } from 'vitepress'

// Template VitePress con generazione sitemap automatica e SEO ottimizzato
// Sostituisci i placeholder:
// nginx-waf-ai: nome esatto del repository GitHub (es. open-bpm)
// Nginx WAF AI: Titolo leggibile del progetto (es. OpenBPM)
// Machine learning system for nginx Web Application Firewall rule generation and deployment.: Descrizione concisa per SEO e Open Graph
// fabriziosalmi: fabriziosalmi

export default defineConfig({
  title: 'Nginx WAF AI',
  description: 'Machine learning system for nginx Web Application Firewall rule generation and deployment.',
  base: '/nginx-waf-ai/',
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: true,

  // SITEMAP AUTOMATICO
  // Genera automaticamente sitemap.xml in fase di build con tutti gli URL indicizzati
  sitemap: {
    hostname: 'https://fabriziosalmi.github.io/nginx-waf-ai/',
  },

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/nginx-waf-ai/favicon.svg' }],
    ['link', { rel: 'apple-touch-icon', href: '/nginx-waf-ai/favicon.svg' }],
    ['link', { rel: 'canonical', href: 'https://fabriziosalmi.github.io/nginx-waf-ai/' }],
    ['meta', { name: 'theme-color', content: '#10b981' }],
    ['meta', { name: 'color-scheme', content: 'dark light' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'Nginx WAF AI' }],
    ['meta', { property: 'og:description', content: 'Machine learning system for nginx Web Application Firewall rule generation and deployment.' }],
    ['meta', { property: 'og:url', content: 'https://fabriziosalmi.github.io/nginx-waf-ai/' }],
    ['meta', { property: 'og:image', content: 'https://fabriziosalmi.github.io/nginx-waf-ai/favicon.svg' }],
    ['meta', { name: 'twitter:card', content: 'summary' }],
    ['meta', { name: 'twitter:title', content: 'Nginx WAF AI' }],
    ['meta', { name: 'twitter:description', content: 'Machine learning system for nginx Web Application Firewall rule generation and deployment.' }],
    ['meta', { name: 'twitter:image', content: 'https://fabriziosalmi.github.io/nginx-waf-ai/favicon.svg' }],
    ['meta', { name: 'robots', content: 'index, follow, max-image-preview:large' }],
    [
      'script',
      { type: 'application/ld+json' },
      JSON.stringify({
        '@context': 'https://schema.org',
        '@graph': [
          {
            '@type': 'SoftwareApplication',
            '@id': 'https://fabriziosalmi.github.io/nginx-waf-ai/#software',
            name: 'Nginx WAF AI',
            operatingSystem: 'Cross-platform',
            applicationCategory: 'DeveloperApplication',
            description: 'Machine learning system for nginx Web Application Firewall rule generation and deployment.',
            url: 'https://fabriziosalmi.github.io/nginx-waf-ai/',
            license: 'https://opensource.org/licenses/MIT',
            codeRepository: 'https://github.com/fabriziosalmi/nginx-waf-ai',
            author: {
              '@type': 'Person',
              name: 'Fabrizio Salmi',
              url: 'https://github.com/fabriziosalmi',
            },
          },
          {
            '@type': 'WebSite',
            '@id': 'https://fabriziosalmi.github.io/nginx-waf-ai/#website',
            url: 'https://fabriziosalmi.github.io/nginx-waf-ai/',
            name: 'Nginx WAF AI Documentation',
            description: 'Machine learning system for nginx Web Application Firewall rule generation and deployment.',
            publisher: {
              '@type': 'Person',
              name: 'Fabrizio Salmi',
              url: 'https://github.com/fabriziosalmi',
            },
            inLanguage: 'en-US',
          },
        ],
      }),
    ],
  ],

  themeConfig: {
    siteTitle: 'Nginx WAF AI',

    nav: [
      { text: 'Guide', link: '/guide/introduction', activeMatch: '/guide/(introduction|quickstart|installation)/' },
      { text: 'Production', link: '/guide/production', activeMatch: '/guide/production' },
      { text: 'REST API', link: '/guide/api', activeMatch: '/guide/api' },
      { text: 'Changelog', link: '/guide/changelog' },
      { text: 'GitHub', link: 'https://github.com/fabriziosalmi/nginx-waf-ai' },
    ],

    sidebar: [
      {
        text: 'Overview & Getting Started',
        items: [
          { text: 'Introduction', link: '/guide/introduction' },
          { text: 'Quick Start (Docker)', link: '/guide/quickstart' },
          { text: 'Manual Installation', link: '/guide/installation' },
        ],
      },
      {
        text: 'Deployment & Operations',
        items: [
          { text: 'Production Setup', link: '/guide/production' },
          { text: 'Implementation Audit', link: '/guide/audit' },
        ],
      },
      {
        text: 'API & Releases',
        items: [
          { text: 'REST API Reference', link: '/guide/api' },
          { text: 'Changelog', link: '/guide/changelog' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/fabriziosalmi/nginx-waf-ai' },
    ],

    search: {
      provider: 'local',
      options: {
        detailedView: true,
      },
    },

    outline: {
      level: [2, 3],
      label: 'On this page',
    },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © Fabrizio Salmi',
    },

    docFooter: {
      prev: 'Previous',
      next: 'Next',
    },
  },

  markdown: {
    theme: {
      light: 'github-light',
      dark: 'github-dark',
    },
  },
})
