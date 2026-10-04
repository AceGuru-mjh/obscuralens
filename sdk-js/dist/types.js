/**
 * Response payload types for the ObscuraLens REST API (v6.x).
 *
 * These interfaces describe what the server *actually returns* — they are the
 * source of truth being `obscuralens/web/app.py`. The server is the contract:
 * every type is deliberately tolerant (optional fields, index signatures via
 * `Record<string, unknown>` bases) so unknown or future keys never break
 * compilation. Each interface's JSDoc names the endpoint it models.
 *
 * Numeric IDs are `number`, ISO timestamps are `string`, and "loose" nested
 * blocks stay `Record<string, unknown>`.
 *
 * @module obscuralens-sdk/types
 */
/** Readonly tuple of every {@link LookupKind} (order matches the server). */
export const KINDS = [
    "ip", "phone", "username", "email", "domain", "url", "crypto", "hash",
    "cve", "asn", "mac", "iban", "imei", "coords",
    "vin", "flight", "mmsi", "app", "bssid", "plate",
];
/**
 * Field each tracker uses to echo back the queried target — mirrors
 * `_TARGET_KEY` in `obscuralens/web/app.py` (e.g. `phone` → `phone_number`,
 * `crypto` → `address`).
 */
export const TARGET_KEYS = {
    ip: "ip",
    phone: "phone_number",
    username: "username",
    email: "email",
    domain: "domain",
    url: "url",
    crypto: "address",
    hash: "hash",
    cve: "cve",
    asn: "asn",
    mac: "mac",
    iban: "iban",
    imei: "imei",
    coords: "coords",
    vin: "vin",
    flight: "flight",
    mmsi: "mmsi",
    app: "app",
    bssid: "bssid",
    plate: "plate",
};
