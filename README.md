# Goldbless

Goldbless is a Node.js and PostgreSQL website. Registration uses a phone number, an eight-digit numeric password, and email verification by OTP. Login uses the phone and password; password recovery verifies the account's phone and registered email with an emailed OTP.

## Local setup

1. Rotate the database password and service keys that were previously shared in chat. Do not reuse those values.
2. Copy `.env.example` to `.env` and enter the newly rotated values locally. Never put secrets in browser JavaScript or commit `.env`.
3. Set a one-time `BOOTSTRAP_INVITE_CODE` for the first account. It works only while the users table is empty; after the first registration, normal existing invite codes are required.
4. Real deposits are intentionally disabled in this demo. Never send money to a wallet based on this local preview.
5. Run `npm install`, then `npm start`.
6. Open `http://localhost:3001`.

The server applies `schema.sql` on startup. Neon requires TLS; keep `sslmode=require` in `DATABASE_URL`. Passwords are stored using scrypt hashes. For production email delivery, verify a sending domain in Resend and use its approved `FROM_EMAIL`. Cloudinary values are optional and are not used by the current site.

## Money movement

- The account balance comes only from confirmed ledger entries. The live-deposit API currently returns `503` and does not accept deposits.
- The quantify page is a browser-only demonstration. Its `Demo` balance and simulated 1.5% changes are not USDT, are not stored as assets, and cannot be withdrawn.
- A withdrawal can be requested only against confirmed ledger funds, with a minimum of 20 USDT. Pending requests reserve funds. An administrator cannot resolve one before 72 hours have elapsed.
- Mark a withdrawal `paid` only after sending the USDT; include the actual payout transaction ID. A `rejected` request releases its reservation.
- No live yield or investment-return engine is implemented. Do not present the demo calculations as profits or advertise returns without a real, auditable source and reviewed terms.

Admin endpoints require the `x-admin-token` header set to `ADMIN_API_TOKEN`. Keep that token server-side and use HTTPS in production. The manual admin endpoints are an operational starter, not a substitute for automated transaction verification, access-controlled admin tooling, legal review, or production security assessment.