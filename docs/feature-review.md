# Ownerlane feature review

Reviewed: 17 July 2026

This is a product-readiness review of the current application, not a security certification. Scores reflect how complete each workflow feels for an early business marketplace.

## Current feature scorecard

| Area | What works today | Readiness | Main gap |
|---|---|---:|---|
| Marketplace discovery | Public live listings, confidentiality gating, keyword/region/sector/price filters, price sorting, list and map views, pagination | 8/10 | More sector-specific filters and search analytics |
| Buyer workflow | Detailed profile, rules-based matches, persistent shortlist, saved searches, event-driven alerts, enquiries, dashboard and subscriptions | 8/10 | Buyer verification and richer qualification evidence |
| Authentication | Verified-email registration, expiring one-time password resets, persistent login throttling and stricter admin sessions | 8/10 | Optional admin MFA and security-event audit views |
| Seller workflow | Profile, listing creation/editing, photos, status changes, enquiries, buyer matches, introductions, staged data rooms and valuation requests | 8/10 | Listing analytics and offer workflow |
| Confidentiality | Blurred restricted data, premium access rules, NDAs, staged disclosure permissions and audited private downloads | 9/10 | Retention controls and external storage hardening |
| Matching | Profile-driven ranking with fit reasons and seller-side buyer matches | 6/10 | Normalised sector criteria and explainable weighting controls |
| Introductions and deals | Request/approve/decline lifecycle, history, deal creation, price, commission and status | 7/10 | Tasks, milestones, messaging and offer/counter-offer history |
| Valuer workflow | Directory/profile, request assignment, accept/decline/update and digest support | 5/10 | Verification, availability, scope/quote management and billing |
| Billing | Stripe checkout, webhooks, subscription state and customer portal | 7/10 | Failed-payment recovery and entitlement audit views |
| Admin | Role directories, listing approval, enquiries, matches, introductions, data-room access, audit log, deals, subscriptions, content and impersonation | 8/10 | Operational reporting and bulk actions |
| Notifications | Persistent notification centre, unread state, immediate/weekly/off preferences, deduplicated saved-search alerts and transaction events | 8/10 | Delivery analytics, per-event controls and background workers |
| Reporting | Deal/commission records and dashboard counts | 3/10 | Funnel, time-to-stage, listing engagement and revenue analytics |
| Multi-sector data model | First-class sectors, configurable attributes and legacy compatibility | 7/10 | Admin-managed sector schemas and buyer criteria migration |

## Improvements delivered in this release

- Exposed the existing keyword, region and sector search controls on the marketplace.
- Added named saved searches with reusable result links and per-search weekly email alerts.
- Added saved-search management to the buyer dashboard.
- Moved shortlists from browser sessions into the database so they persist across devices and logins.
- Migrated any legacy session shortlist into the buyer's persistent shortlist on first use.
- Removed remaining care-home-specific empty-shortlist copy.
- Added ownership checks, uniqueness constraints, migration coverage and workflow tests for the new buyer tools.
- Added a first-class sector catalogue with configurable listing attributes.
- Migrated legacy care listings into compatible normalized sectors without dropping the old fields.
- Added exact minor-unit guide price, revenue and EBITDA values with currency support.
- Added marketplace price filtering and low/high price sorting.
- Added email verification for every new buyer, seller and valuer account.
- Added signed, expiring and single-use password-reset links with account-safe request responses.
- Added persistent failed-login throttling without storing raw email or IP identities.
- Added session rotation, opt-in remember-me and idle/absolute limits for admin sessions.
- Added a persistent notification centre with unread counts and ownership-safe read controls.
- Added immediate, weekly-digest and off email preferences with retryable delivery state.
- Added deduplicated saved-search/profile alerts when listings become live.
- Added notifications for enquiries, introduction changes and valuation requests/statuses.
- Added a privacy-safe activity and audit log for authentication, sensitive listing access, document downloads, notifications and administrator actions.
- Added staged listing data rooms with document categories, retained version history and per-introduction disclosure permissions.
- Added immediate access revocation, secure audited downloads and buyer notifications for new documents and access changes.

Saved-search matches are included in the protected weekly digest task. Immediate delivery is available for transaction and data-room events when selected in notification preferences.

## Recommended roadmap

### P0 — launch confidence and conversion

1. **Normalised sector model — delivered.** First-class sectors, configurable attributes and compatibility migration are now in place.
2. **Authentication hardening — core delivered.** Verified email, password reset, login throttling and stronger admin sessions are in place; optional admin MFA remains a later enhancement.
3. **Notification centre and saved-search delivery — delivered.** Persisted, deduplicated in-app events now support immediate, weekly or disabled email delivery.
4. **Money data migration — delivered.** Listings now store price, revenue and EBITDA in integer minor units plus currency, with legacy display fallbacks.
5. **Activity and audit log — delivered.** Sensitive access, status changes, admin actions, document downloads and notification delivery are recorded.

### P1 — transaction workflow

1. **Staged data room — delivered.** Documents are organised by disclosure stage with version history, per-introduction permissions and audited access.
2. **Buyer qualification.** Add identity/business checks, proof-of-funds status, acquisition track record and seller-visible verification badges.
3. **Deal workspace.** Add private messaging, Q&A, tasks, owners, due dates, milestones and reminders around each introduction.
4. **Offers and negotiation.** Capture structured offers, conditions, expiry, counter-offers and accepted-offer history.
5. **Seller analytics.** Show listing views, shortlist counts, enquiry conversion, matched-buyer quality and time in each stage.
6. **Adviser marketplace.** Generalise valuers into adviser categories with verification, coverage, availability, quotes and reviews.

### P2 — intelligence and scale

1. **Market benchmarks and valuation reports** using completed, permissioned and anonymised transaction data.
2. **Explainable assisted matching** that summarises fit and gaps without making autonomous transaction decisions.
3. **Team accounts and permissions** for buyer groups, seller advisers and internal Ownerlane operators.
4. **CRM, accounting and e-sign integrations** plus a versioned API and webhooks.
5. **Portfolio and multi-listing transactions** for groups sold together or in configurable lots.

## Suggested next build

Build buyer qualification next: verification state, proof-of-funds review, acquisition track record and seller-visible trust badges. This adds the evidence sellers need before granting deeper data-room access.
