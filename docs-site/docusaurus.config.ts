import type * as Preset from '@docusaurus/preset-classic';
import type { Config } from '@docusaurus/types';
import airsTheme from './src/css/prism-airs';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'Prisma AIRS CLI',
  tagline:
    'The airs command line for Palo Alto Networks Prisma AIRS: runtime security, DLP, AI red teaming, model security, AI Gateway and AI supply chain',
  favicon: 'img/brand-logo.png',

  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  // Production url + base path for GitHub Pages (https://cdot65.github.io/prisma-airs-cli/).
  url: 'https://cdot65.github.io',
  baseUrl: '/prisma-airs-cli/',

  organizationName: 'cdot65',
  projectName: 'prisma-airs-cli',

  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  markdown: {
    // `.md` -> CommonMark (safe for raw `<`/`{` in generated typedoc/CLI output),
    // `.mdx` -> full MDX (used only by the tab pages that import Tabs/TabItem).
    format: 'detect',
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  themes: ['@docusaurus/theme-mermaid'],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Docs are served at the site root; the landing page is src/pages/index.tsx.
          routeBasePath: '/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    mermaid: {theme: {light: 'dark', dark: 'dark'}, options: {themeVariables: {
      background: '#030609', primaryColor: '#061b29', primaryTextColor: '#f5f8fa',
      primaryBorderColor: '#00ddf2', lineColor: '#8999a6', secondaryColor: '#0b293b', tertiaryColor: '#061b29',
    }}},
    image: 'img/brand-logo.png',
    docs: {
      sidebar: {
        hideable: true,
      },
    },
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    navbar: {
      title: 'Prisma AIRS CLI',
      logo: {
        alt: 'Prisma AIRS CLI',
        src: 'img/brand-logo.png',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docs',
          position: 'left',
          label: 'Docs',
        },
        {
          type: 'docSidebar',
          sidebarId: 'reference',
          position: 'left',
          label: 'Command reference',
        },
        {
          href: 'https://cdot65.github.io/scm-sdk-rs/',
          label: 'SDK',
          position: 'right',
        },
        {
          href: 'https://git.cdot.io/cdot/prisma-airs-cli',
          label: 'Forgejo',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            { label: 'Install', to: '/getting-started/install' },
            { label: 'Upgrading from 7.x', to: '/getting-started/upgrading-from-typescript' },
            { label: 'Configuration', to: '/getting-started/configuration' },
            { label: 'Command reference', to: '/reference/commands/' },
          ],
        },
        {
          title: 'More',
          items: [
            { label: 'scm-sdk (Rust SDK)', href: 'https://cdot65.github.io/scm-sdk-rs/' },
            { label: 'Forgejo', href: 'https://git.cdot.io/cdot/prisma-airs-cli' },
            { label: 'npm', href: 'https://www.npmjs.com/package/@cdot65/prisma-airs-cli' },
            { label: 'crates.io', href: 'https://crates.io/crates/airs-cli' },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} cdot65. Built with Docusaurus.`,
    },
    prism: {
      theme: airsTheme,
      darkTheme: airsTheme,
      additionalLanguages: ['bash', 'json', 'yaml', 'python', 'powershell', 'toml', 'diff'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
