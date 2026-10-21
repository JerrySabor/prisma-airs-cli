import React, {type ReactNode} from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './index.module.css';
const paths = [["01", "Install airs", "Homebrew, npm, cargo or a release tarball: one self-contained executable.", "/getting-started/install"], ["02", "Coming from 7.x?", "Import your TypeScript CLI tenants once and update your scripts.", "/getting-started/upgrading-from-typescript"], ["03", "Configure a tenant", "Create or import a tenant, then check it with airs doctor.", "/getting-started/configuration"], ["04", "Find the right command", "Every command's help, generated from the CLI itself.", "/reference/commands/"]];
export default function Home(): ReactNode {
  return <Layout title="Prisma AIRS CLI" description="airs, the native command line for Prisma AIRS: scan prompts, manage runtime profiles, DLP, red teaming, model security, AI Gateway and AI supply chain from one terminal."><main>
    <section className={styles.hero} aria-labelledby="hero-title">
      <div><p className={styles.eyebrow}>PRISMA AIRS / CLI</p><h1 id="hero-title">Security at your fingertips.<br /><span>From one terminal.</span></h1>
      <p className={styles.lead}><code>airs</code> is the native command line for Prisma AIRS. Scan prompts, manage runtime profiles and DLP, run red-team assessments, and operate AI Gateway from one self-contained executable.</p><div className={styles.actions}><Link className="button button--primary button--lg" to="/getting-started/install">Get started →</Link><Link className={styles.secondary} to="/reference/commands/">Command reference ↗</Link></div><p className={styles.platforms}>NATIVE · TENANT-AWARE · FAIL-CLOSED</p></div>
      <div className={styles.artwork}><img src={useBaseUrl('/img/brand-logo.png')} alt="Prisma AIRS CLI shield and prism spectrum" width="1254" height="1254" fetchPriority="high" /><div className={styles.pillRow}><span className={styles.pill}>Secure by design</span><span className={styles.pill}>Developer first</span></div></div>
    </section>
    <section className={styles.paths} aria-labelledby="paths-title"><div className={styles.sectionIntro}><p className={styles.eyebrow}>BUILD · CONNECT · PROTECT · SCALE</p><h2 id="paths-title">Turn intent into action.</h2><p>Choose a starting point. Go from your first request to a repeatable security workflow.</p></div><div className={styles.grid}>{paths.map(([number,title,description,to]) => <Link className={styles.path} to={to} key={number}><span className={styles.number}>{number}</span><h3>{title}</h3><p>{description}</p><span className={styles.arrow} aria-hidden="true">↗</span></Link>)}</div></section>
    <section className={styles.quick}><div><p className={styles.eyebrow}>THE PRISMA AIRS TOOLKIT</p><h2>Build a safer tomorrow.</h2><p>The CLI is built on scm-sdk, the Rust SDK for Strata Cloud Manager and Prisma AIRS.</p></div><div className={styles.actions}><Link to="https://cdot65.github.io/scm-sdk-rs/">SDK →</Link><Link to="https://crates.io/crates/airs-cli">crates.io →</Link><Link to="https://www.npmjs.com/package/@cdot65/prisma-airs-cli">npm →</Link></div></section>
  </main></Layout>;
}
