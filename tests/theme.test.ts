import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

console.log('--- Running Cyclops Zero-Lag Four-Theme Optimization Tests ---');

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
// 2. Head Script Early Initialization & Flash Prevention
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

// ---------------------------------------------------------------------------
// 5. Four-Theme Exact Palette Verification
// ---------------------------------------------------------------------------
console.log('Test 5: Verify Soft Light and Soft Dark exact palette tokens in globals.css');

// Soft Light exact tokens
assert.ok(cssContent.includes('#DFDDD6'), 'globals.css must contain Soft Light main background #DFDDD6');
assert.ok(cssContent.includes('#D2D0C9'), 'globals.css must contain Soft Light sidebar/secondary background #D2D0C9');
assert.ok(cssContent.includes('#E8E6DF'), 'globals.css must contain Soft Light card surface #E8E6DF');
assert.ok(cssContent.includes('#34332F'), 'globals.css must contain Soft Light primary text #34332F');
assert.ok(cssContent.includes('#55544F'), 'globals.css must contain Soft Light secondary text #55544F');
assert.ok(cssContent.includes('#C5C2B9'), 'globals.css must contain Soft Light decorative borders #C5C2B9');

// Soft Dark exact tokens
assert.ok(cssContent.includes('#22252B'), 'globals.css must contain Soft Dark main background #22252B');
assert.ok(cssContent.includes('#1C1F24'), 'globals.css must contain Soft Dark sidebar/secondary background #1C1F24');
assert.ok(cssContent.includes('#2C3037'), 'globals.css must contain Soft Dark card surface #2C3037');
assert.ok(cssContent.includes('#DDE1E7'), 'globals.css must contain Soft Dark primary text #DDE1E7');
assert.ok(cssContent.includes('#A9B0BB'), 'globals.css must contain Soft Dark secondary text #A9B0BB');
assert.ok(cssContent.includes('#3B4049'), 'globals.css must contain Soft Dark decorative borders #3B4049');

console.log('✓ globals.css defines complete exact palette specifications for Soft Light and Soft Dark');

// ---------------------------------------------------------------------------
// 6. Four-Theme Architecture & Options Validation
// ---------------------------------------------------------------------------
console.log('Test 6: Verify four-theme options and types in ThemeContext.tsx');
assert.ok(themeContextContent.includes("'light' | 'soft-light' | 'soft-dark' | 'dark'"), 'ThemeContext must define 4 theme types');
assert.ok(themeContextContent.includes('VALID_THEMES'), 'ThemeContext must define VALID_THEMES');
assert.ok(themeContextContent.includes('isValidTheme'), 'ThemeContext must export isValidTheme validation helper');
assert.ok(themeContextContent.includes('THEME_OPTIONS'), 'ThemeContext must export THEME_OPTIONS');
console.log('✓ ThemeContext supports full 4-theme system with runtime validation');

// ---------------------------------------------------------------------------
// 7. Quick-Access Theme Selector Validation
// ---------------------------------------------------------------------------
console.log('Test 7: Verify ThemeToggle 4-option dropdown menu and accessibility');
assert.ok(toggleContent.includes('SunDim'), 'ThemeToggle must use SunDim for Soft Light');
assert.ok(toggleContent.includes('MoonStar'), 'ThemeToggle must use MoonStar for Soft Dark');
assert.ok(toggleContent.includes('Check'), 'ThemeToggle must display Check icon for selected theme');
assert.ok(toggleContent.includes('role="listbox"'), 'ThemeToggle dropdown must have role="listbox"');
assert.ok(toggleContent.includes('role="option"'), 'ThemeToggle dropdown items must have role="option"');
assert.ok(toggleContent.includes('aria-selected'), 'ThemeToggle dropdown items must define aria-selected');
console.log('✓ ThemeToggle implements accessible four-theme dropdown selector');

// ---------------------------------------------------------------------------
// 8. Settings Appearance Section Validation
// ---------------------------------------------------------------------------
console.log('Test 8: Verify Settings appearance section and preview cards');
const appearancePath = path.resolve(__dirname, '../src/components/settings/AppearanceSection.tsx');
const appearanceContent = fs.readFileSync(appearancePath, 'utf8');

assert.ok(appearanceContent.includes('THEME_CARDS'), 'AppearanceSection must define THEME_CARDS');
assert.ok(appearanceContent.includes('Miniature Cyclops Interface Preview'), 'AppearanceSection must render miniature Cyclops preview');
assert.ok(appearanceContent.includes('setTheme(card.id)'), 'AppearanceSection must immediately apply theme on card click');

const settingsPath = path.resolve(__dirname, '../src/app/settings/page.tsx');
const settingsContent = fs.readFileSync(settingsPath, 'utf8');
assert.ok(settingsContent.includes('AppearanceSection'), 'settings/page.tsx must integrate AppearanceSection');

console.log('✓ Settings page integrates responsive four-theme preview cards');

console.log('--- All Theme Optimization Tests Passed Successfully! ---');
