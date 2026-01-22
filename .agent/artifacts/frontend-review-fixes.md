# Frontend Review - Implementation Plan

## Overview
This document outlines the changes needed to bring the JellyHA cards into compliance with Web Interface Guidelines.

## Issues to Fix

### 1. Accessibility Issues

#### Pagination Buttons
- **Location**: Lines 1076-1082, 1131-1137
- **Issue**: Aria labels are generic ("Go to page X")
- **Fix**: Improve aria-label to include context and current state
- **Priority**: High

#### Images
- **Location**: Lines 1174-1181, 1311-1318
- **Issue**: Missing explicit width/height attributes (causes CLS)
- **Fix**: Add width="140" height="210" to all poster images
- **Priority**: High

### 2. Performance Issues

#### Layout Reads in Render
- **Location**: Line 247
- **Issue**: `offsetHeight` read during render causes layout thrashing
- **Fix**: Remove forced reflow, use CSS-only solution or move to useEffect
- **Priority**: Medium

### 3. Internationalization

#### Date Formatting
- **Location**: Lines 1396-1408
- **Issue**: Using `toLocaleDateString` instead of `Intl.DateTimeFormat`
- **Fix**: Replace with proper Intl API usage
- **Priority**: Medium

### 4. Typography

#### Ellipsis Characters
- **Location**: Multiple locations (loading states, truncation)
- **Issue**: Using three dots "..." instead of ellipsis character "…"
- **Fix**: Replace all instances
- **Priority**: Low

### 5. Animation

#### Reduced Motion Support
- **Location**: Lines 225, 250, 345, 469
- **Issue**: Animations don't respect `prefers-reduced-motion`
- **Fix**: Add media query check and conditional animation
- **Priority**: High

### 6. Touch Interaction

#### Touch Action
- **Location**: Interactive elements (buttons, media items)
- **Issue**: Missing `touch-action: manipulation` to prevent double-tap zoom
- **Fix**: Add to CSS for all interactive elements
- **Priority**: Medium

## Implementation Steps

1. Fix accessibility issues (images, aria-labels)
2. Add reduced motion support
3. Fix date formatting with Intl API
4. Remove layout reads from render
5. Add touch-action CSS
6. Replace ellipsis characters
7. Test all changes

## Testing Checklist

- [ ] Images load without layout shift
- [ ] Screen readers announce pagination correctly
- [ ] Animations respect reduced motion preference
- [ ] Dates format correctly in different locales
- [ ] Touch interactions work smoothly on mobile
- [ ] No console warnings about layout thrashing
