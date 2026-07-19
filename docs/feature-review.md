# Ownerlane feature review

Reviewed: 19 July 2026

This is a product-readiness review of the current application, not a security certification. Scores reflect how complete each workflow feels for an early business marketplace.

## Current feature scorecard

| Area | What works today | Readiness | Main gap |
|---|---|---:|---|
| Marketplace discovery | Public live listings, confidentiality gating, keyword/region/sector/price filters, price sorting, list and map views, pagination | 8/10 | More sector-specific filters and search analytics |
| Buyer workflow | Detailed profile, reviewed qualification, proof-of-funds evidence, trust badges, matches, shortlist, saved searches, alerts, enquiries and subscriptions | 9/10 | Team buying groups and mandate approval |
| Authentication | Verified-email registration, expiring one-time password resets, persistent login throttling and stricter admin sessions | 8/10 | Optional admin MFA and security-event audit views |
| Seller workflow | Profile, listing management, enquiries, buyer matches, introductions, staged data rooms, structured offers, valuation requests and privacy-safe analytics | 9/10 | Portfolio tools and team permissions |
| Confidentiality | Blurred restricted data, premium access rules, NDAs, staged disclosure permissions and audited private downloads | 9/10 | Retention controls and external storage hardening |
| Matching | Profile-driven ranking with fit reasons and seller-side buyer matches | 6/10 | Normalised sector criteria and explainable weighting controls |
| Introductions and deals | Request/approve/decline lifecycle, private workspaces, tasks, milestones, structured offer negotiation, deal creation, price, commission and status | 9/10 | E-signatures and completion workflow |
| Adviser workflow | Multi-discipline directory, verification, coverage, availability, private requests, versioned quotes, engagement status and completed-work reviews | 8/10 | Evidence renewal, conflicts workflow and adviser billing |
| Billing | Stripe checkout, webhooks, subscription state and customer portal | 7/10 | Failed-payment recovery and entitlement audit views |
| Admin | Role directories, listing approval, enquiries, matches, introductions, data-room access, audit log, deals, subscriptions, content and impersonation | 8/10 | Operational reporting and bulk actions |
| Notifications | Persistent notification centre, unread state, immediate/weekly/off preferences, deduplicated saved-search alerts and transaction events | 8/10 | Delivery analytics, per-event controls and background workers |
| Reporting | Seller listing engagement, conversion funnels, buyer quality, time-to-stage, listing comparisons and deal/commission records | 7/10 | Platform revenue analytics and scheduled reports |
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
- Added buyer qualification with private proof-of-funds evidence, administrator review decisions and seller-visible trust badges.
- Added declared acquisition track records without exposing private evidence to sellers.
- Added private deal workspaces with participant messaging, resolvable Q&A, assigned tasks, due dates, reminders and milestones.
- Added exact structured offers with terms, conditions, optional expiry dates and permanent counter-offer chains.
- Added participant-controlled acceptance, rejection and withdrawal, plus automatic accepted-price and deal synchronisation.
- Added privacy-safe listing view and shortlist activity measurement using one-way visitor identifiers, with seller and administrator self-views excluded.
- Added seller date/listing filters, engagement trends, conversion funnels, buyer-quality summaries, time-in-stage reporting and listing comparisons.
- Generalised the valuer framework into a multi-discipline adviser marketplace while retaining legacy valuation requests.
- Added independent administrator verification, availability and coverage filters, private scopes, versioned quotes, engagement status, expiry processing and completed-engagement reviews.

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
2. **Buyer qualification — delivered.** Identity, business and proof-of-funds review plus acquisition track records and seller-visible trust badges are in place.
3. **Deal workspace — delivered.** Approved introductions now include private messaging, resolvable Q&A, assigned tasks, due dates, reminders and milestones.
4. **Offers and negotiation — delivered.** Exact monetary offers, conditions, expiry, counter-offers, participant responses and accepted-offer history are tied to each introduction.
5. **Seller analytics — delivered.** Listing views, unique visitors, shortlist activity, conversion, matched-buyer quality, time in stage and per-listing comparisons are available without exposing browsing identities.
6. **Adviser marketplace — delivered.** Valuers now participate in a broader adviser directory with disciplines, verification, coverage, availability, private scoped requests, quote history and reviews.

### P2 — intelligence and scale

1. **Market benchmarks and valuation reports** using completed, permissioned and anonymised transaction data.
2. **Explainable assisted matching** that summarises fit and gaps without making autonomous transaction decisions.
3. **Team accounts and permissions** for buyer groups, seller advisers and internal Ownerlane operators.
4. **CRM, accounting and e-sign integrations** plus a versioned API and webhooks.
5. **Portfolio and multi-listing transactions** for groups sold together or in configurable lots.

## Suggested next build

Build permissioned market benchmarks and valuation reports next, using completed and anonymised transaction data with minimum-sample safeguards.
