/**
 * JWT Pre-request Script (Internal Services)
 * - Caches token until expiry
 * - Avoids token churn
 * - Demo-safe secret handling
 */

const issuer = pm.environment.get("jwt_issuer");
const audience = pm.environment.get("jwt_audience");
const secret = pm.environment.get("jwt_secret");

const cachedToken = pm.environment.get("jwt_token");
const expiry = pm.environment.get("jwt_expiry");

if (cachedToken && expiry && Date.now() < expiry) {
    pm.request.headers.upsert({
        key: "Authorization",
        value: `Bearer ${cachedToken}`
    });
    return;
}

function base64url(obj) {
    return CryptoJS.enc.Base64.stringify(
        CryptoJS.enc.Utf8.parse(JSON.stringify(obj))
    ).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

const now = Math.floor(Date.now() / 1000);

const header = { alg: "HS256", typ: "JWT" };
const payload = {
    iss: issuer,
    aud: audience,
    iat: now,
    exp: now + 300
};

const encodedHeader = base64url(header);
const encodedPayload = base64url(payload);
const signature = CryptoJS.HmacSHA256(
    `${encodedHeader}.${encodedPayload}`,
    secret
).toString(CryptoJS.enc.Base64)
 .replace(/=+$/, "")
 .replace(/\+/g, "-")
 .replace(/\//g, "_");

const token = `${encodedHeader}.${encodedPayload}.${signature}`;

pm.environment.set("jwt_token", token);
pm.environment.set("jwt_expiry", Date.now() + (5 * 60 * 1000));

pm.request.headers.upsert({
    key: "Authorization",
    value: `Bearer ${token}`
});
