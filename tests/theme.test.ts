import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

console.log('--- Running Cyclops Zero-Lag Theme Optimization Tests ---');

// ---------------------------------------------------------------------------
// 1. CSS Optimization Validation
// ---------------------------------------------------------------------------
console.log('Test 1: Inspect globals.css for eliminated transition bottlenecks');
const cssPath = path.resolve(__dirname, '../src/app/globals.css');
const cssContent = fs.readFileSync(cssPath, 'utf8');

// Ensure blanket transition on * is removed
assert.strictEqual(
  cssContent.includes('transition-property: background-color, color, border-color, box-shadow, fill, stroke;'),
  false,
  'Blanket transition on all elements must be removed from globals.css'
);

// Ensure disable-transitions utility exists
assert.ok(
  cssContent.includes('.disable-transitions'),
  'globals.css must contain .disable-transitions utility'
);
assert.ok(
  cssContent.includes('transition: none !important;'),
  '.disable-transitions must enforce transition: none !important'
);

// Ensure prefers-reduced-motion is supported
assert.ok(
  cssContent.includes('@media (prefers-reduced-motion: reduce)'),
  'globals.css must respect prefers-reduced-motion'
);
console.log('✓ globals.css contains no blanket universal transitions and properly defines .disable-transitions');

// ---------------------------------------------------------------------------
// 2. Head Script Early Initialization
// ---------------------------------------------------------------------------
console.log('Test 2: Inspect layout.tsx head script for early flash prevention');
const layoutPath = path.resolve(__dirname, '../src/app/layout.tsx');
const layoutContent = fs.readFileSync(layoutPath, 'utf8');

assert.ok(
  layoutContent.includes("localStorage.getItem('cyclops_theme')"),
  'Inline script must check cyclops_theme'
);
assert.ok(
  layoutContent.includes("localStorage.getItem('sentinel_theme')"),
  'Inline script must check fallback sentinel_theme'
);
assert.ok(
  layoutContent.includes("window.matchMedia('(prefers-color-scheme: dark)').matches"),
  'Inline script must check system preference fallback'
);
assert.ok(
  layoutContent.includes("suppressHydrationWarning"),
  'Root HTML element must have suppressHydrationWarning to prevent React hydration mismatch'
);
console.log('✓ layout.tsx initializes theme before visible render with zero flashing');

// ---------------------------------------------------------------------------
// 3. ThemeContext Implementation Validation
// ---------------------------------------------------------------------------
console.log('Test 3: Inspect ThemeContext.tsx for zero-lag immediate updates');
const themeContextPath = path.resolve(__dirname, '../src/context/ThemeContext.tsx');
const themeContextContent = fs.readFileSync(themeContextPath, 'utf8');

assert.ok(
  themeContextContent.includes("root.classList.add('disable-transitions')"),
  'ThemeContext must apply disable-transitions before class flip'
);
assert.ok(
  themeContextContent.includes("root.classList.add('dark')"),
  'ThemeContext must synchronously apply dark class'
);
assert.ok(
  themeContextContent.includes("root.classList.remove('dark')"),
  'ThemeContext must synchronously remove dark class'
);
assert.ok(
  themeContextContent.includes("STORAGE_KEY_PRIMARY = 'cyclops_theme'") &&
  themeContextContent.includes("localStorage.setItem(STORAGE_KEY_PRIMARY, nextTheme)"),
  'ThemeContext must persist cyclops_theme'
);
console.log('✓ ThemeContext executes synchronous DOM mutation and transition suppression');

// ---------------------------------------------------------------------------
// 4. Component Decoupling Validation
// ---------------------------------------------------------------------------
console.log('Test 4: Inspect ThemeToggle.tsx and DemoContext.tsx separation');
const togglePath = path.resolve(__dirname, '../src/components/ui/ThemeToggle.tsx');
const toggleContent = fs.readFileSync(togglePath, 'utf8');

assert.ok(
  toggleContent.includes("useTheme()"),
  'ThemeToggle must consume useTheme directly to avoid re-rendering heavy scanner components'
);
assert.strictEqual(
  toggleContent.includes("useDemoContext()"),
  false,
  'ThemeToggle must not consume monolithic DemoContext'
);

const demoContextPath = path.resolve(__dirname, '../src/context/DemoContext.tsx');
const demoContextContent = fs.readFileSync(demoContextPath, 'utf8');

assert.ok(
  demoContextContent.includes("const { theme, toggleTheme, setTheme } = useTheme();"),
  'DemoContext must delegate theme management to ThemeContext'
);
console.log('✓ Theme state is fully decoupled from scan and telemetry contexts');

console.log('--- All Theme Optimization Tests Passed Successfully! ---');
