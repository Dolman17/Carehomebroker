# Ownerlane feature review

Reviewed: 17 July 2026

This is a product-readiness review of the current application, not a security certification. Scores reflect how complete each workflow feels for an early business marketplace.

## Current feature scorecard

| Area | What works today | Readiness | Main gap |
|---|---|---:|---|
| Marketplace discovery | Public live listings, confidentiality gating, keyword/region/sector/price filters, price sorting, list and map views, pagination | 8/10 | More sector-specific filters and search analytics |
| Buyer workflow | Detailed profile, rules-based matches, persistent shortlist, saved searches, enquiries, dashboard, subscriptions | 7/10 | Automated alert delivery and buyer verification |
| Seller workflow | Profile, listing creation/editing, photos, status changes, enquiries, buyer matches, introductions and valuation requests | 7/10 | Listing analytics, document room and offer workflow |
| Confidentiality | Blurred restricted data, premium access rules, NDAs and private seller documents | 8/10 | Staged disclosure permissions and audit trail |
| Matching | Profile-driven ranking with fit reasons and seller-side buyer matches | 6/10 | Normalised sector criteria and explainable weighting controls |
| Introductions and deals | Request/approve/decline lifecycle, history, deal creation, price, commission and status | 7/10 | Tasks, milestones, messaging and offer/counter-offer history |
| Valuer workflow | Directory/profile, request assignment, accept/decline/update and digest support | 5/10 | Verification, availability, scope/quote management and billing |
| Billing | Stripe checkout, webhooks, subscription state and customer portal | 7/10 | Failed-payment recovery and entitlement audit views |
| Admin | Role directories, listing approval, enquiries, matches, introductions, deals, subscriptions, content and impersonation | 7/10 | Activity log, operational reporting and bulk actions |
| Notifications | Email helpers and weekly digest task | 4/10 | In-app notification centre and event-driven alerts |
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

Saved-search matches are included in the existing protected weekly digest task. Immediate event-triggered alerts remain a later notification-centre enhancement.

## Recommended roadmap

### P0 — launch confidence and conversion

1. **Normalised sector model — delivered.** First-class sectors, configurable attributes and compatibility migration are now in place.
2. **Authentication hardening.** Add verified email, password reset, login throttling and optional MFA for admins.
3. **Notification centre and saved-search delivery.** Create persisted notifications, deduplicate matching-listing alerts and send digest or immediate email according to buyer preference.
4. **Money data migration — delivered.** Listings now store price, revenue and EBITDA in integer minor units plus currency, with legacy display fallbacks.
5. **Activity and audit log.** Record sensitive access, status changes, admin actions and document downloads.

### P1 — transaction workflow

1. **Staged data room.** Organise documents by disclosure stage, apply per-introduction permissions and record access.
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

Build authentication hardening next: verified email, secure password-reset links, login throttling and stronger admin sessions. Follow it with the persisted notification centre so saved searches and marketplace events can be delivered reliably without relying only on the weekly digest task.
