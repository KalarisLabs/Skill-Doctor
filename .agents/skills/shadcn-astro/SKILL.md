---
name: shadcn-astro
description: Best practices for implementing shadcn/ui components, Radix UI primitives, Lucide icons, and Tailwind v4 in Astro applications.
---

# shadcn/ui & Astro Frontend Standards

Use this skill when building or styling components in Astro with React islands and Tailwind CSS v4.

## Key Guidelines
1. **Astro Component Hydration:**
   - Static presentation elements belong in native `.astro` files.
   - Interactive forms, dynamic state, and animated controls belong in React islands loaded with `client:load` or `client:idle`.
2. **Tailwind v4 Token Structure:**
   - Use CSS variables mapped via `@theme inline` inside `globals.css`.
   - Apply semantic utility classes (`bg-background`, `text-foreground`, `border-border`, `text-muted-foreground`).
3. **Component Reusability:**
   - Follow standard `components/ui/` primitives (Card, Badge, Button, Progress, Input, Tabs, Dialog, Alert).
   - Use `clsx` and `tailwind-merge` (`cn` helper) for dynamic class composition.
4. **Icons & Visual Cues:**
   - Use `lucide-react` for crisp vector iconography.
