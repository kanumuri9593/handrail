# handrail site

Single static page. The file has no `<html>`/`<head>` wrapper because it was previewed as a Claude artifact;
`build.sh` wraps it into `dist/index.html` for any static host (Cloudflare Pages, GitHub Pages).

    sh site/build.sh && npx wrangler pages deploy site/dist --project-name handrail
