# Ownerlane feature review

Reviewed: 17 July 2026

This is a product-readiness review of the current application, not a security certification. Scores reflect how complete each workflow feels for an early business marketplace.

## Current feature scorecard

| Area | What works today | Readiness | Main gap |
|---|---|---:|---|
| Marketplace discovery | Public live listings, confidentiality gating, keyword/region/sector filters, list and map views, pagination | 7/10 | Price sorting and richer sector-specific filters |
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
| Multi-sector data model | Generic Ownerlane copy over a legacy care-focused schema | 4/10 | First-class sector model and configurable sector attributes |

## Improvements delivered in this release

- Exposed the existing keyword, region and sector search controls on the marketplace.
- Added named saved searches with reusable result links and per-search weekly email alerts.
- Added saved-search management to the buyer dashboard.
- Moved shortlists from browser sessions into the database so they persist across devices and logins.
- Migrated any legacy session shortlist into the buyer's persistent shortlist on first use.
- Removed remaining care-home-specific empty-shortlist copy.
- Added ownership checks, uniqueness constraints, migration coverage and workflow tests for the new buyer tools.

Saved-search matches are included in the existing protected weekly digest task. Immediate event-triggered alerts remain a later notification-centre enhancement.

## Recommended roadmap

### P0 — launch confidence and conversion

1. **Normalised sector model.** Replace legacy `care_type`, `beds` and CQC-shaped assumptions with sectors and configurable attributes while maintaining compatibility during migration.
2. **Authentication hardening.** Add verified email, password reset, login throttling and optional MFA for admins.
3. **Notification centre and saved-search delivery.** Create persisted notifications, deduplicate matching-listing alerts and send digest or immediate email according to buyer preference.
4. **Money data migration.** Store prices, revenue and EBITDA as integer minor units plus currency instead of display strings, enabling reliable filtering and reporting.
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

Build the normalised sector model first, because it removes the largest constraint created by the original care-home mock-up. Pair it with money fields and compatibility adapters so existing routes and data continue to work while new sectors gain appropriate fields and filters.
