// Explicit browser origin allowlist shared by Express and Socket.IO.
// Set CORS_ALLOWED_ORIGINS to a comma-separated list of trusted frontend origins.
// Example: CORS_ALLOWED_ORIGINS=http://localhost:5173,http://192.168.1.50:5173
const DEFAULT_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"];

function allowedOrigins() {
  const configured = (process.env.CORS_ALLOWED_ORIGINS || "")
    .split(",")
    .map(value => value.trim())
    .filter(Boolean);
  return [...new Set([...DEFAULT_ORIGINS, ...configured])];
}

function corsOrigin(origin, callback) {
  // Requests without Origin are not browser cross-origin requests.
  if (!origin || allowedOrigins().includes(origin)) return callback(null, true);
  return callback(new Error("Origin not allowed by CORS"));
}

module.exports = { allowedOrigins, corsOrigin };
