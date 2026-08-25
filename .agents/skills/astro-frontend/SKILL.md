---
name: astro-frontend
description: Specialist for Astro, React, Tailwind v4, and shadcn/ui.
---

# Astro Frontend Engineering

Use this skill when modifying the web application (`web/src`, `web/components`, `web/pages`).

## Architectural Domain
The web interface is built with Astro and deployed on Cloudflare Pages/Workers. It relies on React for interactive islands and Tailwind v4 for styling.

## Best Practices
- **Astro Islands:** Ensure React components are hydrated correctly using `client:load`, `client:idle`, etc. Keep static content in Astro files.
- **Tailwind v4:** Use CSS variables defined in `@theme` blocks inside `globals.css`.
- **shadcn/ui:** Follow the standard component structures.
- **Security:** Ensure SSRF protection is in place on all API routes that fetch external resources.
