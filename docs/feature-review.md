# Ownerlane feature review

Reviewed: 20 July 2026

This is a product-readiness review of the current application, not a security certification. Scores reflect how complete each workflow feels for an early business marketplace.

## Current feature scorecard

| Area | What works today | Readiness | Main gap |
|---|---|---:|---|
| Marketplace discovery | Public live listings, confidentiality gating, keyword/region/sector/price filters, price sorting, list and map views, pagination | 8/10 | More sector-specific filters and search analytics |
| Buyer workflow | Detailed profile, qualification, formally approved mandates, matches, shared team shortlists and searches, alerts, enquiries and subscriptions | 9/10 | Mandate renewal and institutional reporting |
| Authentication | Verified-email registration, expiring one-time password resets, persistent login throttling, stricter admin sessions and mandatory administrator passkeys | 9/10 | Security-event investigation views and recovery operations |
| Seller workflow | Profile, team listing collaboration and billing, configurable portfolios, advisers, enquiries, buyer matches, introductions, staged data rooms, offers, valuation requests and analytics | 9/10 | Bulk operations |
| Confidentiality | Blurred restricted data, premium access rules, NDAs, staged disclosure permissions and audited private downloads | 9/10 | Retention controls and external storage hardening |
| Matching | Deterministic assisted ranking with visible weights, criterion evidence, gaps, missing-data coverage and buyer/seller/admin explanations | 9/10 | Feedback calibration and administrator weighting policy |
| Introductions and deals | Request/approve/decline lifecycle, private workspaces, tasks, milestones, offers, completion conditions, Signable execution, two-party handover and deal synchronisation | 9/10 | Identity assurance and funds-flow integrations |
| Adviser workflow | Multi-discipline directory, verification, coverage, availability, private requests, versioned quotes, engagement status and completed-work reviews | 8/10 | Evidence renewal, conflicts workflow and adviser billing |
| Billing | Personal and seat-based team Stripe checkout, idempotent lifecycle webhooks, failed-payment grace periods, automatic recovery, customer portal and entitlement audit views | 9/10 | Scheduled reconciliation reports |
| Admin | Role directories, listing approval, enquiries, matches, introductions, data-room access, audit log, deals, subscriptions, content and impersonation | 8/10 | Operational reporting and bulk actions |
| Notifications | Persistent notification centre, unread state, immediate/weekly/off preferences, deduplicated saved-search alerts and transaction events | 8/10 | Delivery analytics, per-event controls and background workers |
| Reporting | Seller listing engagement, conversion funnels, buyer quality, time-to-stage, listing comparisons and deal/commission records | 7/10 | Platform revenue analytics and scheduled reports |
| Multi-sector data model | First-class sectors, configurable attributes and legacy compatibility | 7/10 | Admin-managed sector schemas and buyer criteria migration |
| Integrations | Scoped read-only API tokens, versioned endpoints, signed retryable webhooks, CRM CSV export and native Signable execution | 8/10 | Native CRM apps and accounting sync |
| Portfolio transactions | Confidential multi-listing opportunities sold as a whole, by configurable lot, or either way | 8/10 | Portfolio-level data rooms and offer allocation |
| Transaction completion | Required checklists, conditions, private checksummed Signable documents and controlled two-party handover | 9/10 | Identity assurance and completion payments |

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
- Added scoped API credentials stored only as keyed hashes and invalidated when team access is removed.
- Added versioned read-only profile, listing and introduction endpoints that reuse marketplace confidentiality policies.
- Added user- and team-scoped HTTPS webhooks with HMAC signatures, SSRF destination checks, delivery history and bounded retries.
- Added role-scoped CRM CSV export with spreadsheet-formula injection protection.
- Added confidential multi-listing portfolios with whole-sale, lot-sale or flexible transaction structures.
- Added seller lot allocation, per-lot guide prices and availability, publication safeguards and premium buyer enquiries targeted to a whole portfolio or selected lot.
- Reused listing and team permissions throughout, and automatically returns affected portfolios to draft when their composition or a constituent listing changes.
- Added portfolio-aware introduction requests so qualified whole-portfolio and lot enquiries enter the governed approval and deal-workspace workflow.
- Added assigned completion checklists and conditions with required-item blockers and confirmation invalidation when the record changes.
- Added private checksummed signature-ready documents with separate buyer and seller acknowledgements and clear non-reliance wording.
- Added a two-party controlled handover that alone can complete the introduction and deal, mark the relevant listings sold, and update whole portfolios or selected lots.
- Added mandatory phishing-resistant passkeys and recent-authentication step-up for administrator tools.
- Added native Signable envelope submission, authenticated and idempotent webhook handling, authoritative provider reconciliation, party status tracking and private checksummed signed-copy storage.
- Added Stripe failed-payment recovery with a configurable grace period, persistent customer prompts, terminal-state restriction and verified automatic restoration after payment.
- Added an append-only subscription entitlement history showing Stripe or administrator source, provider transition, access decision, timestamp and reason.
- Added formally submitted, versioned buyer mandates that require verified qualification, administrator approval and an unchanged acquisition-criteria snapshot before detailed enquiries or seller matching.
- Added seat-based buyer and seller team billing, owner-only checkout and billing management, explicit seat allocation, active-workspace scoping and provider-quantity reconciliation without merging personal and team entitlements.

Saved-search matches are included in the protected weekly digest task. Immediate delivery is available for transaction and data-room events when selected in notification preferences.

## Recommended roadmap

### P0 — launch confidence and conversion

1. **Normalised sector model — delivered.** First-class sectors, configurable attributes and compatibility migration are now in place.
2. **Authentication hardening — delivered.** Verified email, password reset, login throttling, stronger admin sessions and mandatory administrator passkeys are in place.
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

1. **Market benchmarks and valuation reports — delivered.** Completed deals require current buyer and seller consent, administrator publication, anonymous aggregation and a minimum cohort of five; sellers can save reproducible indicative reports.
2. **Explainable assisted matching — delivered.** Buyer, seller and administrator views now share deterministic weighted criteria, fit/gap/missing evidence and a separate coverage score; results never autonomously approve, reject or block a transaction.
3. **Team accounts and permissions — delivered.** Buyer groups share shortlists and searches, seller teams share selected listings and data rooms with advisers, and Ownerlane operators can be organised without team membership granting platform-admin status. Invitations are expiring and email-bound; owner, manager, contributor and viewer permissions are enforced server-side and audited.
4. **Integrations foundation — delivered.** Scoped read-only API access, signed retryable webhooks, a CRM-ready export and native Signable execution are available. Native CRM apps and accounting sync remain future extensions.
5. **Portfolio and multi-listing transactions — delivered.** Sellers can package at least two live listings for sale as a whole, by configurable lot or either way, with listing-level confidentiality, team permissions, targeted buyer enquiries and automatic unpublishing when the package changes.

### P3 — completion and assurance

1. **Transaction completion workflow — delivered.** Portfolio-aware introductions now support assigned completion checklists, conditions, checksummed execution-document tracking and buyer/seller handover confirmation. Administrator status changes cannot bypass the controlled completion gate.
2. **Native electronic signatures — delivered.** Signable envelopes use private document upload, authenticated idempotent callbacks, provider-side status reconciliation and archived signed artifacts. Manual acknowledgements remain available only for documents not sent to Signable.

### P4 — commercial operations

1. **Failed-payment recovery and entitlement audit — delivered.** Stripe lifecycle events now drive grace, restriction and automatic recovery decisions with an append-only administrator history.
2. **Formal buyer mandate approval and team billing — delivered.** Verified buyers submit versioned mandate snapshots for administrator approval, and buyer/seller team owners can purchase and explicitly allocate workspace-scoped paid seats.

## Suggested next build

Add security-event investigation and account-recovery operations next. Identity assurance and regulated completion-payment integrations should follow only after their operational and compliance models are defined.
