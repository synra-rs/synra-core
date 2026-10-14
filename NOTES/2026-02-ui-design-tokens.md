# UI design tokens, and how a plugin's interface stays consistent with the host

A decision record. It answers one question: **host 界面和插件界面怎样看起来是同一个产品，而插件仍然在自己的隔离上下文里?**

## The decision

1. **The host uses antd.** Its components, its theme.
2. **A plugin draws whatever it likes** — its own Vue, its own components, its own copy of antd if it wants one.
3. **The host injects CSS custom properties, prefixed `--synra-`, into every plugin context.** That is the whole styling
   contract between them.
4. **No JSON-schema renderer.** A declarative UI layer was considered and dropped: it cannot express a chat view, a file
   browser or a chart, and a schema that grows special cases for those is worse than the freedom it removes.
5. **A plugin does not declare which tokens it uses.** Tokens are an API: they are stable, and changing one is a breaking
   change with a version bump — not something to be negotiated per plugin.

## Why the token layer is the *only* shared styling

Isolation is a security property and consistency is a presentation property. An earlier draft of the plugin design treated
them as one subject, and that is how a project ends up with either no isolation or twenty visual languages.

A plugin's interface runs in its **own WebView, or a sandboxed iframe with its own origin**. That boundary is what stops a
plugin reading the host's state — and it also means:

- The host's component **instances cannot be shared**. A Vue component, a reactive object, an antd `ConfigProvider` — none of
  them cross a realm.
- The host's **antd cannot be reached** by a plugin. So "give plugins antd" is not a decision anyone can make; the question
  answers itself.
- Therefore a plugin that wants antd **bundles it**, and the host cannot prevent that, nor should it try.

What *can* cross the boundary is **data**. CSS custom properties are the only styling data the platform already has a
mechanism for, because a property set on a document's root is what a nested document's `var()` resolves against — once the
host puts it there.

So the contract is: **the plugin owns its structure, the host owns the values.**

```text
Host WebView
  └── plugin WebView / iframe          (its own origin, its own realm)
        ├── the plugin's own styles    — it decides everything structural
        └── var(--synra-color-primary) — a value it did not choose
```

## What that costs, honestly

| | |
| --- | --- |
| **Solved** | Colour, radius, spacing, font size, light/dark — one change in the host moves every plugin. |
| **Not solved** | A plugin on antd 5.20 renders slightly differently from the host on 5.24. Component internals are the plugin's business, and the token layer cannot reach them. |
| **Accepted** | A plugin may look nothing like the host if it tries. The tokens make consistency easy, not mandatory. Users see a plugin that ignored them as the plugin's choice — which it is. |

## The tokens

Names map one-to-one onto antd v5's token names. A plugin author reads the antd documentation and finds the same word, so
there is no second vocabulary to learn.

Values are **not** listed here. They are generated from the host's theme in one place, and a value copied into this file
would be a second source that drifts. What is fixed is the **names and what each means**.

### Brand and semantic colour

| Variable | antd token | Means |
| --- | --- | --- |
| `--synra-color-primary` | `colorPrimary` | the product's colour |
| `--synra-color-primary-hover` | `colorPrimaryHover` | a pointer is over it |
| `--synra-color-primary-active` | `colorPrimaryActive` | it is being pressed |
| `--synra-color-primary-bg` | `colorPrimaryBg` | a selected row, a tag — primary as a wash |
| `--synra-color-success` | `colorSuccess` | an operation succeeded |
| `--synra-color-warning` | `colorWarning` | something needs attention |
| `--synra-color-error` | `colorError` | something failed |
| `--synra-color-info` | `colorInfo` | neutral information |
| `--synra-color-link` | `colorLink` | text that is a link |

`hover` and `active` are injected **because antd derives them in JavaScript**. A plugin that only reads
`--synra-color-primary` and hands it to `ConfigProvider` gets the right base colour and a *derived* hover colour that does not
match the host's. Injecting the derived values is what makes the mismatch impossible rather than merely unlikely.

### Background and surface

| Variable | antd token | Means |
| --- | --- | --- |
| `--synra-color-bg-layout` | `colorBgLayout` | the page behind everything |
| `--synra-color-bg-container` | `colorBgContainer` | a card, a panel |
| `--synra-color-bg-elevated` | `colorBgElevated` | a popup, a dropdown — above the page |
| `--synra-color-bg-spotlight` | `colorBgSpotlight` | the ground of a tooltip |
| `--synra-color-bg-mask` | `colorBgMask` | what dims the page under a modal |

### Text

| Variable | antd token | Means |
| --- | --- | --- |
| `--synra-color-text` | `colorText` | body text |
| `--synra-color-text-secondary` | `colorTextSecondary` | a description, a caption |
| `--synra-color-text-tertiary` | `colorTextTertiary` | a hint |
| `--synra-color-text-quaternary` | `colorTextQuaternary` | a placeholder |
| `--synra-color-text-disabled` | — | text that cannot be acted on |
| `--synra-color-text-inverse` | `colorTextLightSolid` | text on a filled colour |

### Border and divider

| Variable | antd token | Means |
| --- | --- | --- |
| `--synra-color-border` | `colorBorder` | an input's outline |
| `--synra-color-border-secondary` | `colorBorderSecondary` | a lighter outline |
| `--synra-color-split` | `colorSplit` | a divider line |

### Type

| Variable | antd token | Means |
| --- | --- | --- |
| `--synra-font-family` | `fontFamily` | the interface's face |
| `--synra-font-family-code` | `fontFamilyCode` | a monospaced face |
| `--synra-font-size` | `fontSize` | the body size everything else scales from |
| `--synra-font-size-sm` | `fontSizeSM` | smaller |
| `--synra-font-size-lg` | `fontSizeLG` | larger |
| `--synra-font-size-xl` | `fontSizeXL` | larger still |
| `--synra-font-size-heading-1` | `fontSizeHeading1` | a page title |
| `--synra-font-size-heading-2` | `fontSizeHeading2` | a section |
| `--synra-font-size-heading-3` | `fontSizeHeading3` | a sub-section |
| `--synra-font-size-heading-4` | `fontSizeHeading4` | a heading in a card |
| `--synra-font-size-heading-5` | `fontSizeHeading5` | the smallest heading |
| `--synra-line-height` | `lineHeight` | a unitless multiplier |
| `--synra-font-weight-strong` | `fontWeightStrong` | emphasis |

### Space, corner, depth, motion

| Variable | antd token | Means |
| --- | --- | --- |
| `--synra-size-unit` | `sizeUnit` | the base every space is a multiple of |
| `--synra-size-step` | `sizeStep` | the multiple, as a number |
| `--synra-padding-xs` … `-xl` | `paddingXS` … `paddingXL` | space inside a box |
| `--synra-margin-xs` … `-xl` | `marginXS` … `marginXL` | space between boxes |
| `--synra-border-radius-sm` | `borderRadiusSM` | a small corner |
| `--synra-border-radius` | `borderRadius` | the default corner |
| `--synra-border-radius-lg` | `borderRadiusLG` | a large corner |
| `--synra-box-shadow` | `boxShadow` | a raised surface |
| `--synra-box-shadow-secondary` | `boxShadowSecondary` | a floating surface |
| `--synra-motion-duration-fast` | `motionDurationFast` | a state change |
| `--synra-motion-duration-mid` | `motionDurationMid` | an appearing element |
| `--synra-motion-duration-slow` | `motionDurationSlow` | a moving panel |
| `--synra-motion-ease` | `motionEaseInOut` | the curve those durations use |

### Mode and density

| Variable | Values | Means |
| --- | --- | --- |
| `--synra-theme-mode` | `light` \| `dark` | which palette is in force, for a plugin choosing an image or an icon |
| `--synra-color-scheme` | `light` \| `dark` | fed to the CSS `color-scheme` property, so a plugin's native controls follow |
| `--synra-density` | `default` \| `compact` | the user's density setting |

## Three things that are easy to get wrong

### A shadow must be split, not copied

antd's `boxShadow` is a comma-separated list:

```css
0 6px 16px 0 rgb(0 0 0 / 8%), 0 3px 6px -4px rgb(0 0 0 / 12%), 0 9px 28px 8px rgb(0 0 0 / 5%)
```

A comma inside a custom property's value is read as a separator when `var()` expands it, so the list breaks. **One variable
per layer**, or a single-layer approximation: `--synra-shadow-1`, `--synra-shadow-2`, `--synra-shadow-3`.

### A token change is not a repaint

antd v5 generates its styles in JavaScript and caches them. Changing a custom property does not recompute an already-rendered
component's derived styles, so a plugin that switches its `ConfigProvider` only on mount shows half a dark theme after a mode
change.

So the injection is **two channels**, and the second is not optional:

```ts
// 1. The values, as CSS custom properties on the plugin document's root.
// 2. A notification, so the plugin can re-derive what it caches.
synra.theme.subscribe((tokens: ThemeTokens) => { /* rebuild ConfigProvider */ })
synra.theme.current(): ThemeTokens        // for the first render, no race
```

### Where the properties are put depends on the isolation tier

| Tier | How the host reaches it |
| --- | --- |
| L1 — a separate WebView | the host writes the properties into the document it loaded; no plugin cooperation needed |
| L2, L3 — a sandboxed iframe | an iframe has its own document and does **not** inherit from the parent, so the host injects a `<style>` into the frame, or the plugin applies a token object the host hands it at startup |

L1 is the desktop case and the one that must work; L2/L3 are the fallback, and they need the second channel even for the
initial values.

## What this means for the host's own code

The host must have **one** place where a theme becomes tokens. Not a stylesheet with the colours in it and a script that
happens to agree — one source, from which three things are produced:

1. the host's own antd `ConfigProvider` theme;
2. the `:root` block injected into a plugin context;
3. the `ThemeTokens` object `synra.theme.current()` returns.

Two sources would drift, and drift is the thing this decision exists to prevent.

## Not decided here

- **The host's actual palette.** These are names and meanings; the values are the interface design's subject.
- **Whether the host ships a component kit for plugins.** A plugin cannot receive the host's components, so such a kit would
  be a *copy* of some components at a published version. Useful, and not part of this decision.
