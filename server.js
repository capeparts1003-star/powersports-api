// server.js - Powersports API
// Run with: node server.js

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const Stripe = require("stripe");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { prisma } = require("./prismaClient");
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();
const PORT = process.env.PORT || 4000;

// Stripe config
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PLATFORM_FEE_PERCENT = 0.1; // 10%
const STRIPE_API_VERSION = "2022-11-15";
const APP_BASE_URL = process.env.APP_BASE_URL || "http://localhost:4000";
const STRIPE_ACCOUNT_RETURN_URL =
  process.env.STRIPE_ACCOUNT_RETURN_URL ||
  `${APP_BASE_URL}/stripe/onboarding/return`;
const STRIPE_ACCOUNT_REFRESH_URL =
  process.env.STRIPE_ACCOUNT_REFRESH_URL ||
  `${APP_BASE_URL}/stripe/onboarding/refresh`;

if (!STRIPE_SECRET_KEY) {
  console.warn(
    "Warning: STRIPE_SECRET_KEY is not set. Payment endpoints will be disabled."
  );
}
if (!STRIPE_WEBHOOK_SECRET) {
  console.warn(
    "Warning: STRIPE_WEBHOOK_SECRET is not set. Stripe webhook endpoint will be disabled."
  );
}

const stripe = STRIPE_SECRET_KEY
  ? new Stripe(STRIPE_SECRET_KEY, { apiVersion: STRIPE_API_VERSION })
  : null;

// Auth config
const JWT_SECRET =
  process.env.JWT_SECRET || "dev-insecure-jwt-secret-change-me";
const JWT_EXPIRES_IN = "7d";

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many auth attempts, please try again later." },
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many payment attempts, please slow down." },
});

const analyticsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware
app.use(cors());
// Use JSON for most routes, but skip the Stripe webhook (raw body needed for signature verification).
app.use((req, res, next) => {
  if (req.originalUrl === "/webhooks/stripe") {
    return next();
  }
  return bodyParser.json()(req, res, next);
});
app.set("trust proxy", 1);

// Default categories list
const categoryDefinitions = [
  {
    name: "ATV Parts",
    subcategories: [
      "Engine",
      "Exhaust",
      "Electrical",
      "Fuel System",
      "Frame",
      "Suspension",
      "Drivetrain",
      "Tires & Wheels",
      "Plastics / Body",
      "Winches & Racks",
      "Performance",
    ],
  },
  {
    name: "UTV Parts",
    subcategories: [
      "Engine",
      "Exhaust",
      "Electrical",
      "Fuel System",
      "Transmission & Drivetrain",
      "Cages & Roofs",
      "Suspension",
      "Tires & Wheels",
      "Storage & Racks",
      "Plastics / Body",
      "Performance",
    ],
  },
  {
    name: "Car & Truck Parts",
    subcategories: [
      "Engine",
      "Brakes",
      "Transmission & Drivetrain",
      "Exhaust",
      "Electrical",
      "Exterior",
      "Interior",
      "Suspension & Steering",
      "Lighting",
      "Performance",
    ],
  },
  {
    name: "Motorcycle Parts",
    subcategories: [
      "Engine",
      "Suspension",
      "Transmission & Drivetrain",
      "Brakes",
      "Wheels & Tires",
      "Fairings / Body",
      "Exhaust",
      "Electrical",
      "Seats",
      "Performance",
    ],
  },
  {
    name: "Jet Ski / PWC Parts",
    subcategories: [
      "Engine",
      "Exhaust",
      "Impellers",
      "Covers",
      "Seats",
      "Intake / Pump",
      "Electrical",
      "Hull & Body",
      "Performance",
    ],
  },
  {
    name: "Boat Parts",
    subcategories: [
      "Engine",
      "Fuel System",
      "Cooling System",
      "Navigation",
      "Contols & Steering",
      "Electrical",
      "Hull & Deck",
      "Propellers",
      "Covers & Biminis",
      "Hardware & Fittings",
      "Electronics",
      "Performance",
    ],
  },
  {
    name: "Snowmobile Parts",
    subcategories: [
      "Engine",
      "Exhaust",
      "Cooling System",
      "Fuel System",
      "Electrical",
      "Clutches & Drivetrain",
      "Seat",
      "Tracks",
      "Skis & Suspension",
      "Body & Plastics",
      "Performance",
    ],
  },
  {
    name: "Scooter Parts",
    subcategories: [
      "Engine",
      "Exhaust",
      "Fuel System",
      "Tires & Wheels",
      "Frame",
      "Suspension",
      "Brakes",
      "Body Panels",
      "Controls",
      "Seats & Racks",
    ],
  },
  {
    name: "Tires & Wheels",
    subcategories: [
      "ATV / UTV Tires",
      "Motorcycle Tires",
      "Car & Truck Tires",
      "Rims & Wheel Sets",
    ],
  },
  {
    name: "Accessories",
    subcategories: [
      "Storage & Bags",
      "Covers",
      "Racks",
      "Phone / GPS Mounts",
    ],
  },
  {
    name: "Riding Gear",
    subcategories: [
      "Helmets",
      "Jackets",
      "Gloves",
      "Boots",
      "Pants & Suits",
    ],
  },
  {
    name: "Tools & Shop Equipment",
    subcategories: [
      "Hand Tools",
      "Lift Stands & Ramps",
      "Diagnostic Tools",
      "Fluids & Chemicals",
    ],
  },
];

const defaultCategories = categoryDefinitions.map((c) => c.name);

// Helpers
const pendingTwoFactor = new Map();

function signJwt(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function verifyJwt(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded?.sub;
  } catch {
    return null;
  }
}

function getUserIdForRequest(req) {
  const authHeader = req.header("Authorization") || "";
  if (authHeader.toLowerCase().startsWith("bearer ")) {
    const token = authHeader.slice(7).trim();
    const jwtUserId = verifyJwt(token);
    if (jwtUserId) return jwtUserId;
  }
  return null;
}

async function getOrCreateStripeCustomer(userId) {
  if (!stripe) {
    throw new Error("Stripe is not configured on the server.");
  }
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    throw new Error("User not found for Stripe customer creation.");
  }
  if (user.stripeCustomerId) {
    return user.stripeCustomerId;
  }
  const customer = await stripe.customers.create({
    metadata: { appUserId: userId },
  });
  await prisma.user.update({
    where: { id: userId },
    data: { stripeCustomerId: customer.id },
  });
  return customer.id;
}

async function ensureSellerStripeAccount(user) {
  if (!stripe) {
    throw new Error("Stripe is not configured on the server.");
  }
  if (!user) {
    throw new Error("User not found for Stripe account creation.");
  }
  if (user.sellerStripeAccountId) {
    return user.sellerStripeAccountId;
  }

  const account = await stripe.accounts.create({
    type: "express",
    email: user.email,
    capabilities: {
      card_payments: { requested: true },
      transfers: { requested: true },
    },
    metadata: { appUserId: user.id },
  });

  await prisma.user.update({
    where: { id: user.id },
    data: { sellerStripeAccountId: account.id },
  });

  return account.id;
}

async function markPaymentStatusPrisma(
  paymentIntentId,
  status,
  failureReason = null
) {
  if (!paymentIntentId) return;
  const data =
    status === "succeeded"
      ? {
          paid: true,
          paidAt: new Date(),
          paymentFailed: false,
          paymentFailureReason: null,
        }
      : {
          paid: false,
          paidAt: null,
          paymentFailed: true,
          paymentFailureReason: failureReason || null,
        };

  await prisma.$transaction([
    prisma.purchase.updateMany({
      where: { paymentIntentId },
      data,
    }),
    prisma.sale.updateMany({
      where: { paymentIntentId },
      data,
    }),
  ]);
}

function buildListingFilter(search) {
  const and = [];
  const where = {};

  const query = (search.query || "").toString().trim();
  const camera = (search.camera || "").toString().trim();
  const includeSold = !!search.includeSold;

  if (query) {
    where.OR = [
      { title: { contains: query, mode: "insensitive" } },
      { description: { contains: query, mode: "insensitive" } },
    ];
  }
  if (search.category) {
    and.push({ category: search.category });
  }
   if (search.subcategory) {
     and.push({ subcategory: search.subcategory });
   }
  if (camera) {
    and.push({ camera: { contains: camera, mode: "insensitive" } });
  }
  if (typeof search.minPrice === "number") {
    and.push({ price: { gte: search.minPrice } });
  }
  if (typeof search.maxPrice === "number") {
    and.push({ price: { lte: search.maxPrice } });
  }
  if (!includeSold) {
    and.push({ NOT: { status: "sold" } });
  }
  if (and.length) {
    where.AND = and;
  }
  return where;
}

async function getPushTokensForUser(userId) {
  if (!userId) return [];
  try {
    const tokens = await prisma.pushToken.findMany({
      where: { userId },
      select: { expoPushToken: true },
    });
    return tokens.map((t) => t.expoPushToken).filter(Boolean);
  } catch (err) {
    console.error("getPushTokensForUser error:", err);
    return [];
  }
}

async function sendPushToUser(userId, payload) {
  const tokens = await getPushTokensForUser(userId);
  if (!tokens.length) return;

  const messages = tokens.map((token) => ({
    to: token,
    title: payload.title,
    body: payload.body,
    data: payload.data || {},
    sound: "default",
  }));

  try {
    await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(messages),
    });
  } catch (err) {
    console.error("sendPushToUser error:", err);
  }
}

// Webhook
app.post(
  "/webhooks/stripe",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    if (!stripe || !STRIPE_WEBHOOK_SECRET) {
      return res.status(503).send("Stripe webhook not configured.");
    }

    const sig = req.headers["stripe-signature"];
    if (!sig) {
      return res.status(400).send("Missing stripe-signature header.");
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Webhook signature verification failed:", err);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      switch (event.type) {
        case "payment_intent.succeeded": {
          const pi = event.data.object;
          await markPaymentStatusPrisma(pi.id, "succeeded");
          break;
        }
        case "payment_intent.payment_failed": {
          const pi = event.data.object;
          const reason = pi.last_payment_error?.message || "Payment failed";
          await markPaymentStatusPrisma(pi.id, "failed", reason);
          break;
        }
        default:
          break;
      }
    } catch (err) {
      console.error("Webhook handler error:", err);
      return res.status(500).send("Webhook processing error.");
    }

    res.json({ received: true });
  }
);

// Health
app.get("/", (req, res) => {
  res.json({ ok: true, message: "Powersports API" });
});

// Auth routes are rate-limited
app.use(
  ["/auth/login", "/auth/login-2fa/start", "/auth/login-2fa/verify", "/auth/register"],
  authLimiter
);

// POST /auth/register
app.post("/auth/register", async (req, res) => {
  const { email, username, password, name } = req.body || {};

  if (!email || !username || !password) {
    return res
      .status(400)
      .json({ error: "Email, username, and password are required." });
  }

  // Password policy: at least 8 chars, one number, one special char
  const passwordPolicy = /^(?=.*[0-9])(?=.*[^A-Za-z0-9]).{8,}$/;
  if (!passwordPolicy.test(password)) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters and include a number and a special character.",
    });
  }

  const normalizedEmail = String(email).toLowerCase().trim();
  const normalizedUsername = String(username).trim();
  const rawPassword = String(password);

  if (!normalizedUsername || normalizedUsername.length < 3) {
    return res
      .status(400)
      .json({ error: "Username must be at least 3 characters." });
  }

  const usernameRegex = /^[a-zA-Z0-9._-]+$/;
  if (!usernameRegex.test(normalizedUsername)) {
    return res.status(400).json({
      error:
        "Username can only contain letters, numbers, dots, dashes, and underscores.",
    });
  }

  const hasNumber = /\d/.test(rawPassword);
  const hasSpecial = /[^A-Za-z0-9]/.test(rawPassword);
  if (!hasNumber || !hasSpecial) {
    return res.status(400).json({
      error: "Password must include at least one number and one special character.",
    });
  }

  const hashedPassword = bcrypt.hashSync(rawPassword, 10);

  try {
    const user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        username: normalizedUsername,
        password: hashedPassword,
        name: name
          ? String(name)
          : normalizedUsername || normalizedEmail.split("@")[0],
        twoFactorEnabled: false,
      },
    });

    return res.status(201).json({
      id: user.id,
      email: user.email,
      username: user.username,
      name: user.name,
      twoFactorEnabled: !!user.twoFactorEnabled,
      ratingCount: user.ratingCount,
      ratingAverage: user.ratingAverage,
      token: signJwt(user.id),
    });
  } catch (err) {
    if (err.code === "P2002") {
      return res.status(409).json({ error: "Email or username already exists." });
    }
    console.error("POST /auth/register error:", err);
    return res.status(500).json({ error: "Failed to register user." });
  }
});

// POST /auth/login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res
      .status(400)
      .json({ error: "Email/username and password are required." });
  }

  const identifier = String(email).toLowerCase().trim();
  const pw = String(password);

  const user = await prisma.user.findFirst({
    where: {
      OR: [{ email: identifier }, { username: identifier }],
    },
  });

  if (!user) {
    return res.status(401).json({ error: "Invalid email/username or password." });
  }

  const isHashed = String(user.password || "").startsWith("$2");
  let valid = false;
  if (!isHashed && user.password === pw) {
    valid = true;
    const hashed = bcrypt.hashSync(pw, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashed },
    });
  } else if (isHashed) {
    valid = bcrypt.compareSync(pw, user.password);
  }

  if (!valid) {
    return res
      .status(401)
      .json({ error: "Invalid email/username or password." });
  }

  const token = signJwt(user.id);

  res.json({
    id: user.id,
    email: user.email,
    username: user.username || null,
    name: user.name,
    twoFactorEnabled: !!user.twoFactorEnabled,
    ratingCount: user.ratingCount || 0,
    ratingAverage: user.ratingAverage ?? null,
    token,
  });
});

// POST /auth/login-2fa/start
app.post("/auth/login-2fa/start", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res
      .status(400)
      .json({ error: "Email/username and password are required." });
  }

  const identifier = String(email).toLowerCase().trim();
  const pw = String(password);

  const user = await prisma.user.findFirst({
    where: {
      OR: [{ email: identifier }, { username: identifier }],
    },
  });

  if (!user) {
    return res
      .status(401)
      .json({ error: "Invalid email/username or password." });
  }

  const isHashed = String(user.password || "").startsWith("$2");
  let valid = false;
  if (!isHashed && user.password === pw) {
    valid = true;
    const hashed = bcrypt.hashSync(pw, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashed },
    });
  } else if (isHashed) {
    valid = bcrypt.compareSync(pw, user.password);
  }

  if (!valid) {
    return res
      .status(401)
      .json({ error: "Invalid email/username or password." });
  }

  const twoFactorEnabled = !!user.twoFactorEnabled;

  if (!twoFactorEnabled) {
    return res.json({
      twoFactorRequired: false,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        name: user.name,
        twoFactorEnabled: !!user.twoFactorEnabled,
        ratingCount: user.ratingCount || 0,
        ratingAverage: user.ratingAverage ?? null,
        token: signJwt(user.id),
      },
    });
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 5 * 60 * 1000;
  pendingTwoFactor.set(user.id, { code, expiresAt });
  console.log(
    `2FA code for user ${user.id} (${user.username || user.email}): ${code}`
  );

  return res.json({
    twoFactorRequired: true,
    userId: user.id,
  });
});

// POST /auth/login-2fa/verify
app.post("/auth/login-2fa/verify", async (req, res) => {
  const { userId, code } = req.body || {};

  if (!userId || !code) {
    return res.status(400).json({ error: "userId and code are required." });
  }

  const entry = pendingTwoFactor.get(String(userId));
  if (!entry) {
    return res.status(400).json({ error: "No pending 2FA session for this user." });
  }

  if (Date.now() > entry.expiresAt) {
    pendingTwoFactor.delete(String(userId));
    return res
      .status(400)
      .json({ error: "2FA code has expired. Please login again." });
  }

  if (String(entry.code) !== String(code).trim()) {
    return res.status(401).json({ error: "Invalid 2FA code." });
  }

  pendingTwoFactor.delete(String(userId));

  const user = await prisma.user.findUnique({ where: { id: String(userId) } });
  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }

  return res.json({
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      name: user.name,
      twoFactorEnabled: !!user.twoFactorEnabled,
      ratingCount: user.ratingCount || 0,
      ratingAverage: user.ratingAverage ?? null,
      token: signJwt(user.id),
    },
  });
});

// POST /me/password - change password (authenticated)
app.post("/me/password", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res
      .status(400)
      .json({ error: "Current password and new password are required." });
  }

  const passwordPolicy = /^(?=.*[0-9])(?=.*[^A-Za-z0-9]).{8,}$/;
  if (!passwordPolicy.test(String(newPassword))) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters and include a number and a special character.",
    });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: myId } });
    if (!user || !user.password) {
      return res.status(404).json({ error: "User not found." });
    }

    const ok = bcrypt.compareSync(String(currentPassword), user.password);
    if (!ok) {
      return res.status(401).json({ error: "Current password is incorrect." });
    }

    const hashed = bcrypt.hashSync(String(newPassword), 10);
    await prisma.user.update({
      where: { id: myId },
      data: { password: hashed },
    });

    return res.json({ ok: true, message: "Password updated." });
  } catch (err) {
    console.error("POST /me/password error:", err);
    return res.status(500).json({ error: "Failed to update password." });
  }
});

// GET /me/account
app.get("/me/account", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const user = await prisma.user.findUnique({ where: { id: myId } });
  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }

  res.json({
    id: user.id,
    email: user.email,
    username: user.username,
    name: user.name,
    twoFactorEnabled: !!user.twoFactorEnabled,
    ratingCount: user.ratingCount || 0,
    ratingAverage: user.ratingAverage ?? null,
  });
});

// POST /me/twofactor
app.post("/me/twofactor", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const { enabled } = req.body || {};

  const user = await prisma.user.update({
    where: { id: myId },
    data: { twoFactorEnabled: !!enabled },
  });

  res.json({
    id: user.id,
    twoFactorEnabled: !!user.twoFactorEnabled,
  });
});

// Categories
app.get("/categories", (req, res) => {
  res.json(defaultCategories);
});

// Listings
app.get("/listings", async (req, res) => {
  try {
    const q = (req.query.q || "").toString().trim();
    const camera = (req.query.camera || "").toString().trim();
    const includeSold = req.query.includeSold === "1";

    const where = buildListingFilter({
      query: q,
      camera,
      includeSold,
    });
    const listings = await prisma.listing.findMany({
      where,
      orderBy: { createdAt: "desc" },
    });
    res.json(listings);
  } catch (err) {
    console.error("GET /listings error:", err);
    res.status(500).json({ error: "Failed to load listings." });
  }
});

app.get("/listings/:id", async (req, res) => {
  try {
    const listing = await prisma.listing.findUnique({
      where: { id: String(req.params.id) },
    });
    if (!listing) {
      return res.status(404).send("Listing not found");
    }

    try {
      await prisma.listing.update({
        where: { id: listing.id },
        data: { viewCount: { increment: 1 } },
      });
    } catch (e) {
      console.log("viewCount increment failed", e);
    }

    let sellerRatingAverage = null;
    let sellerRatingCount = 0;
    if (listing.sellerId) {
      const seller = await prisma.user.findUnique({
        where: { id: listing.sellerId },
        select: { ratingAverage: true, ratingCount: true },
      });
      if (seller) {
        sellerRatingAverage =
          typeof seller.ratingAverage === "number" ? seller.ratingAverage : null;
        sellerRatingCount = seller.ratingCount || 0;
      }
    }

    res.json({
      ...listing,
      sellerRatingAverage,
      sellerRatingCount,
    });
  } catch (err) {
    console.error("GET /listings/:id error:", err);
    res.status(500).send("Failed to load listing");
  }
});

// Report listing
app.post("/listings/:id/report", async (req, res) => {
  const reporterId = getUserIdForRequest(req);
  const listingId = String(req.params.id);
  const { reason, note } = req.body || {};

  const allowed = ["Spam"];
  if (!reason || !allowed.includes(reason)) {
    return res.status(400).json({ error: "Invalid reason." });
  }

  try {
    const listing = await prisma.listing.findUnique({
      where: { id: listingId },
      select: { id: true },
    });
    if (!listing) {
      return res.status(404).json({ error: "Listing not found." });
    }

    const report = await prisma.listingReport.create({
      data: {
        listingId,
        reporterId: reporterId || null,
        reason,
        note: note ? String(note).slice(0, 500) : null,
      },
    });

    return res.json(report);
  } catch (err) {
    console.error("POST /listings/:id/report error:", err);
    return res.status(500).json({ error: "Failed to submit report." });
  }
});

app.post("/listings", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const {
    title,
    description,
    price,
    shippingCost,
    mainImage,
    images,
    condition,
    category,
    subcategory,
    year,
    make,
    model,
    camera,
    zipCode,
    localPickup,
    allowOffers,
    status,
  } = req.body || {};

  if (!title || typeof price !== "number") {
    return res.status(400).json({ error: "Missing title or price" });
  }

  const statusVal = (status || "active").toString().toLowerCase();
  if (!["active", "draft"].includes(statusVal)) {
    return res.status(400).json({ error: "Status must be 'active' or 'draft'." });
  }

  try {
    const listing = await prisma.listing.create({
      data: {
        title: String(title),
        description: description ? String(description) : "",
        price: Number(price),
        shippingCost: typeof shippingCost === "number" ? shippingCost : null,
        mainImage: mainImage || null,
        images: Array.isArray(images) ? images : [],
        condition: condition || null,
        category: category || null,
        subcategory: subcategory || null,
        year: year || null,
        make: make || null,
        model: model || null,
        camera: camera ? String(camera) : null,
        zipCode: zipCode || null,
        localPickup: typeof localPickup === "boolean" ? localPickup : false,
        allowOffers: typeof allowOffers === "boolean" ? allowOffers : true,
        status: statusVal,
        sellerId: userId,
      },
    });

    res.status(201).json(listing);
  } catch (err) {
    console.error("POST /listings error:", err);
    res.status(500).json({ error: "Failed to create listing" });
  }
});

app.patch("/listings/:id", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const allowedFields = [
    "title",
    "description",
    "price",
    "shippingCost",
    "mainImage",
    "images",
    "condition",
    "category",
    "subcategory",
    "year",
    "make",
    "model",
    "camera",
    "zipCode",
    "status",
    "localPickup",
    "allowOffers",
  ];

  const data = {};
  for (const key of allowedFields) {
    if (key in req.body) {
      data[key] = req.body[key];
    }
  }

  try {
    const listing = await prisma.listing.update({
      where: { id: String(req.params.id) },
      data,
    });
    res.json(listing);
  } catch (err) {
    console.error("PATCH /listings/:id error:", err);
    res.status(404).send("Listing not found");
  }
});

// Messages
app.get("/me/messages", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const msgs = await prisma.message.findMany({
      where: { OR: [{ toUserId: myId }, { fromUserId: myId }] },
      orderBy: { createdAt: "desc" },
    });
    res.json(msgs);
  } catch (err) {
    console.error("GET /me/messages error:", err);
    res.status(500).json({ error: "Failed to load messages." });
  }
});

app.post("/messages", async (req, res) => {
  const fromUserId = getUserIdForRequest(req);
  if (!fromUserId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { listingId, toUserId, body } = req.body || {};

  if (!listingId || !toUserId || !body) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const listing = await prisma.listing.findUnique({
      where: { id: String(listingId) },
    });
    if (!listing) {
      return res.status(404).json({ error: "Listing not found" });
    }

    const msg = await prisma.message.create({
      data: {
        listingId: String(listingId),
        fromUserId,
        toUserId: String(toUserId),
        body: String(body),
      },
    });

    await prisma.listing.update({
      where: { id: String(listingId) },
      data: { messageCount: { increment: 1 } },
    });

    // Fire-and-forget push notification to the recipient
    sendPushToUser(String(toUserId), {
      title: "New message",
      body: body.length > 100 ? `${body.slice(0, 97)}...` : body,
      data: {
        badgeType: "messages",
        badgeDelta: 1,
        listingId: String(listingId),
      },
    });

    res.status(201).json(msg);
  } catch (err) {
    console.error("POST /messages error:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Sales & Purchases
app.get("/me/sales", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const sales = await prisma.sale.findMany({
      where: { sellerId: myId },
      orderBy: { createdAt: "desc" },
      include: {
        listing: {
          select: {
            id: true,
            title: true,
            sellerId: true,
          },
        },
        returnRequest: true,
      },
    });
    res.json(sales);
  } catch (err) {
    console.error("GET /me/sales error:", err);
    res.status(500).json({ error: "Failed to load sales." });
  }
});

app.get("/me/purchases", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const purchases = await prisma.purchase.findMany({
      where: { buyerId: myId },
      orderBy: { createdAt: "desc" },
      include: { returnRequest: true },
    });
    res.json(purchases);
  } catch (err) {
    console.error("GET /me/purchases error:", err);
    res.status(500).json({ error: "Failed to load purchases." });
  }
});

// POST /purchases/:id/return - buyer requests a return within 14 days
app.post("/purchases/:id/return", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const purchaseId = String(req.params.id);
  const { reason } = req.body || {};
  const allowedReasons = [
    "Arrived Damaged",
    "Dont need anymore",
    "Not as described",
  ];
  if (!reason || !allowedReasons.includes(reason)) {
    return res.status(400).json({ error: "Invalid return reason." });
  }

  try {
    const purchase = await prisma.purchase.findUnique({
      where: { id: purchaseId },
      include: { listing: true, returnRequest: true },
    });
    if (!purchase) {
      return res.status(404).json({ error: "Purchase not found." });
    }
    if (purchase.buyerId !== myId) {
      return res.status(403).json({ error: "You can only request returns on your own purchases." });
    }

    const daysSincePurchase =
      (Date.now() - new Date(purchase.createdAt).getTime()) /
      (1000 * 60 * 60 * 24);
    if (daysSincePurchase > 14) {
      return res
        .status(400)
        .json({ error: "Return window has expired (14 days after purchase)." });
    }

    if (purchase.returnRequest) {
      return res.json(purchase.returnRequest);
    }

    const rr = await prisma.returnRequest.create({
      data: {
        purchaseId,
        buyerId: myId,
        status: "pending",
        reason,
        buyerPaysReturnShipping: reason === "Dont need anymore",
      },
    });

    // Notify seller if possible
    if (purchase.listing?.sellerId) {
      sendPushToUser(purchase.listing.sellerId, {
        title: "Return requested",
        body: `Buyer requested a return on ${purchase.listing.title || "a purchase"}.`,
        data: {
          badgeType: "myGarageAttention",
          badgeDelta: 1,
          purchaseId,
        },
      });
    }

    return res.json(rr);
  } catch (err) {
    console.error("POST /purchases/:id/return error:", err);
    return res.status(500).json({ error: "Failed to request return." });
  }
});

// Seller handles return request
app.patch("/return-requests/:id", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const id = String(req.params.id);
  const { status, reason } = req.body || {};
  const normalized = (status || "").toString().toLowerCase();
  if (!["approved", "rejected"].includes(normalized)) {
    return res
      .status(400)
      .json({ error: "Status must be 'approved' or 'rejected'." });
  }

  try {
    const rr = await prisma.returnRequest.findUnique({
      where: { id },
      include: {
        purchase: {
          include: {
            listing: { select: { sellerId: true, title: true } },
            buyer: { select: { id: true } },
          },
        },
      },
    });
    if (!rr) return res.status(404).json({ error: "Return request not found." });

    if (rr.purchase.listing.sellerId !== myId) {
      return res
        .status(403)
        .json({ error: "You cannot change this return request." });
    }
    if (rr.status !== "pending") {
      return res.status(400).json({ error: "Return request already handled." });
    }

    const updated = await prisma.returnRequest.update({
      where: { id },
      data: {
        status: normalized,
        reason: reason ? String(reason).slice(0, 500) : rr.reason,
      },
    });

    // Notify buyer
    if (rr.purchase.buyer?.id) {
      sendPushToUser(rr.purchase.buyer.id, {
        title: "Return request update",
        body:
          normalized === "approved"
            ? "Seller approved your return request."
            : "Seller rejected your return request.",
        data: {
          badgeType: "purchasesUnshipped",
          badgeDelta: 0,
          returnRequestId: id,
        },
      });
    }

    return res.json(updated);
  } catch (err) {
    console.error("PATCH /return-requests/:id error:", err);
    return res.status(500).json({ error: "Failed to update return request." });
  }
});

// Stripe Connect onboarding for sellers
app.post("/me/stripe/account", paymentLimiter, async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ error: "Stripe is not configured on the server." });
  }
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const accountId = await ensureSellerStripeAccount(user);
    const account = await stripe.accounts.retrieve(accountId);

    return res.json({
      accountId,
      detailsSubmitted: account.details_submitted,
      chargesEnabled: account.charges_enabled,
      payoutsEnabled: account.payouts_enabled,
      requirements: account.requirements?.currently_due || [],
    });
  } catch (err) {
    console.error("POST /me/stripe/account error:", err);
    const message = err?.message || "Could not create Stripe account.";
    return res.status(500).json({ error: message });
  }
});

app.post("/me/stripe/account-link", paymentLimiter, async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ error: "Stripe is not configured on the server." });
  }
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const accountId = await ensureSellerStripeAccount(user);
    const link = await stripe.accountLinks.create({
      account: accountId,
      refresh_url: STRIPE_ACCOUNT_REFRESH_URL,
      return_url: STRIPE_ACCOUNT_RETURN_URL,
      type: "account_onboarding",
    });

    return res.json({ url: link.url, accountId });
  } catch (err) {
    console.error("POST /me/stripe/account-link error:", err);
    const message = err?.message || "Could not create account link.";
    return res.status(500).json({ error: message });
  }
});

app.get("/me/stripe/account", paymentLimiter, async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ error: "Stripe is not configured on the server." });
  }
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }
    if (!user.sellerStripeAccountId) {
      return res.json({ accountId: null, detailsSubmitted: false, chargesEnabled: false, payoutsEnabled: false, requirements: [] });
    }

    const account = await stripe.accounts.retrieve(user.sellerStripeAccountId);
    return res.json({
      accountId: user.sellerStripeAccountId,
      detailsSubmitted: account.details_submitted,
      chargesEnabled: account.charges_enabled,
      payoutsEnabled: account.payouts_enabled,
      requirements: account.requirements?.currently_due || [],
    });
  } catch (err) {
    console.error("GET /me/stripe/account error:", err);
    const message = err?.message || "Could not load Stripe account.";
    return res.status(500).json({ error: message });
  }
});

// Payments: PaymentIntent for PaymentSheet
app.post("/payments/intent", paymentLimiter, async (req, res) => {
  if (!stripe) {
    return res
      .status(500)
      .json({ error: "Stripe is not configured on the server." });
  }

  try {
    const buyerId = getUserIdForRequest(req);
    if (!buyerId) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const { listingId, amount } = req.body || {};

    if (!listingId) {
      return res.status(400).json({ error: "listingId is required." });
    }

    const listing = await prisma.listing.findUnique({
      where: { id: String(listingId) },
      include: { seller: true },
    });
    if (!listing) {
      return res.status(404).json({ error: "Listing not found." });
    }

    if ((listing.status || "").toLowerCase() === "sold") {
      return res.status(400).json({ error: "Listing already sold." });
    }

    const calculatedAmount =
      typeof amount === "number" && amount > 0
        ? Math.round(amount)
        : Math.round((listing.price || 0) + (listing.shippingCost || 0));

    if (!calculatedAmount || calculatedAmount <= 0) {
      return res.status(400).json({ error: "Amount must be a positive number." });
    }

    const appFeeAmount = Math.round(
      calculatedAmount * STRIPE_PLATFORM_FEE_PERCENT
    );

    const customerId = await getOrCreateStripeCustomer(buyerId);
    const ephemeralKey = await stripe.ephemeralKeys.create(
      { customer: customerId },
      { apiVersion: STRIPE_API_VERSION }
    );

    const sellerStripeAccountId =
      listing.seller?.sellerStripeAccountId || null;

    const paymentIntent = await stripe.paymentIntents.create({
      amount: calculatedAmount,
      currency: "usd",
      customer: customerId,
      automatic_payment_methods: { enabled: true },
      ...(sellerStripeAccountId
        ? {
            transfer_data: { destination: sellerStripeAccountId },
            application_fee_amount: appFeeAmount,
          }
        : {}),
      metadata: {
        listingId: listing.id,
        buyerId,
        sellerId: listing.sellerId || "",
      },
    });

    return res.json({
      paymentIntentClientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      customer: customerId,
      ephemeralKey: ephemeralKey.secret,
      merchantDisplayName: "Powersports",
      appFeeAmount,
      amount: calculatedAmount,
      sellerStripeAccountId,
    });
  } catch (err) {
    console.error("payments/intent error:", err);
    const message = err?.message || "Could not create payment intent.";
    return res.status(500).json({ error: message });
  }
});

// Cart checkout (single seller only)
app.post("/me/cart/checkout-intent", paymentLimiter, async (req, res) => {
  try {
    const buyerId = getUserIdForRequest(req);
    if (!buyerId) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    if (!stripe) {
      return res.status(400).json({ error: "Stripe not configured" });
    }

    const cartItems = await prisma.cartItem.findMany({
      where: { userId: buyerId },
      include: { listing: true },
      orderBy: { createdAt: "asc" },
    });

    if (!cartItems.length) {
      return res.status(400).json({ error: "Cart is empty" });
    }

    const sellerIds = new Set(
      cartItems.map((c) => c.listing?.sellerId).filter(Boolean)
    );
    if (sellerIds.size !== 1) {
      return res
        .status(400)
        .json({
          error:
            "Cart must contain items from a single seller. Please checkout separately by seller.",
        });
    }
    const sellerId = [...sellerIds][0];

    const invalid = cartItems.find(
      (c) =>
        !c.listing ||
        (c.listing.status || "").toLowerCase() === "sold"
    );
    if (invalid) {
      return res
        .status(400)
        .json({ error: "Cart has an unavailable item. Refresh and try again." });
    }

    const totalAmount = cartItems.reduce((sum, c) => {
      const qty = Math.max(1, c.quantity || 1);
      const price = c.listing.price || 0;
      const ship = c.listing.shippingCost || 0;
      return sum + qty * (price + ship);
    }, 0);

    if (totalAmount <= 0) {
      return res.status(400).json({ error: "Total must be greater than zero." });
    }

    const seller = await prisma.user.findUnique({ where: { id: sellerId } });
    const sellerStripeAccountId = await ensureSellerStripeAccount(seller);
    const customerId = await getOrCreateStripeCustomer(buyerId);

    const appFeeAmount = Math.round(
      Number(totalAmount) * STRIPE_PLATFORM_FEE_PERCENT
    );

    const paymentIntent = await stripe.paymentIntents.create({
      amount: totalAmount,
      currency: "usd",
      automatic_payment_methods: { enabled: true },
      customer: customerId,
      application_fee_amount: appFeeAmount,
      transfer_data: {
        destination: sellerStripeAccountId,
      },
      metadata: {
        type: "cart",
        buyerId,
        sellerId,
        listingIds: cartItems.map((c) => c.listingId).join(","),
      },
    });

    const ephemeralKey = await stripe.ephemeralKeys.create(
      { customer: customerId },
      { apiVersion: STRIPE_API_VERSION }
    );

    return res.json({
      paymentIntentClientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      customer: customerId,
      ephemeralKey: ephemeralKey.secret,
      merchantDisplayName: "Powersports",
      appFeeAmount,
      amount: totalAmount,
      sellerStripeAccountId,
    });
  } catch (err) {
    console.error("cart/checkout-intent error:", err);
    const message = err?.message || "Could not create cart payment intent.";
    return res.status(500).json({ error: message });
  }
});

app.post("/me/cart/checkout-complete", async (req, res) => {
  const buyerId = getUserIdForRequest(req);
  if (!buyerId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  if (!stripe) {
    return res.status(400).json({ error: "Stripe not configured" });
  }

  const { paymentIntentId } = req.body || {};
  if (!paymentIntentId) {
    return res.status(400).json({ error: "paymentIntentId is required" });
  }

  try {
    const pi = await stripe.paymentIntents.retrieve(paymentIntentId);
    if (pi.status !== "succeeded") {
      return res
        .status(400)
        .json({ error: `PaymentIntent not succeeded (status=${pi.status})` });
    }

    const cartItems = await prisma.cartItem.findMany({
      where: { userId: buyerId },
      include: { listing: true },
      orderBy: { createdAt: "asc" },
    });

    if (!cartItems.length) {
      return res.status(400).json({ error: "Cart is empty" });
    }

    const sellerIds = new Set(
      cartItems.map((c) => c.listing?.sellerId).filter(Boolean)
    );
    if (sellerIds.size !== 1) {
      return res
        .status(400)
        .json({
          error:
            "Cart must contain items from a single seller. Please checkout separately by seller.",
        });
    }
    const sellerId = [...sellerIds][0];

    const totalAmount = cartItems.reduce((sum, c) => {
      const qty = Math.max(1, c.quantity || 1);
      const price = c.listing.price || 0;
      const ship = c.listing.shippingCost || 0;
      return sum + qty * (price + ship);
    }, 0);

    if (pi.amount !== totalAmount) {
      return res.status(400).json({ error: "Payment amount mismatch." });
    }

    const createOps = [];
    const now = new Date();

    for (const c of cartItems) {
      const qty = Math.max(1, c.quantity || 1);
      const lineAmount =
        qty * ((c.listing.price || 0) + (c.listing.shippingCost || 0));
      const appFeeAmount = Math.round(
        Number(lineAmount) * STRIPE_PLATFORM_FEE_PERCENT
      );
      const netAmount = lineAmount - appFeeAmount;

      createOps.push(
        prisma.sale.create({
          data: {
            listingId: c.listingId,
            sellerId: sellerId || buyerId,
            amount: lineAmount,
            appFeeAmount,
            netAmount,
            paymentIntentId,
            paid: true,
            paidAt: now,
            shipped: false,
            paymentFailed: false,
          },
        })
      );
      createOps.push(
        prisma.purchase.create({
          data: {
            listingId: c.listingId,
            buyerId,
            amount: lineAmount,
            appFeeAmount,
            netAmount,
            paymentIntentId,
            paid: true,
            paidAt: now,
            shipped: false,
            paymentFailed: false,
          },
        })
      );
      createOps.push(
        prisma.listing.update({
          where: { id: c.listingId },
          data: { status: "sold" },
        })
      );
    }

    await prisma.$transaction(createOps);
    await prisma.cartItem.deleteMany({ where: { userId: buyerId } });

    res.json({ ok: true, paymentIntentId });
  } catch (err) {
    console.error("cart/checkout-complete error:", err);
    res
      .status(500)
      .json({ error: err?.message || "Failed to finalize cart checkout." });
  }
});

// POST /purchases
app.post("/purchases", async (req, res) => {
  const buyerId = getUserIdForRequest(req);
  if (!buyerId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { listingId, amount, paymentIntentId } = req.body || {};
  if (!listingId || typeof amount !== "number" || amount <= 0) {
    return res.status(400).json({ error: "Missing listingId or valid amount" });
  }

  const listing = await prisma.listing.findUnique({
    where: { id: String(listingId) },
  });
  if (!listing) {
    return res.status(404).json({ error: "Listing not found" });
  }

  const appFeeAmount = Math.round(Number(amount) * STRIPE_PLATFORM_FEE_PERCENT);
  const netToSeller = Number(amount) - appFeeAmount;
  const now = new Date();

  try {
    const [sale, purchase] = await prisma.$transaction([
      prisma.sale.create({
        data: {
          listingId: String(listingId),
          sellerId: listing.sellerId || buyerId,
          amount: Number(amount),
          appFeeAmount,
          netAmount: netToSeller,
          paymentIntentId: paymentIntentId || null,
          paid: true,
          paidAt: now,
          paymentFailed: false,
          paymentFailureReason: null,
          shipped: false,
          trackingNumber: null,
          carrier: null,
          shippedAt: null,
        },
      }),
      prisma.purchase.create({
        data: {
          listingId: String(listingId),
          buyerId,
          amount: Number(amount),
          appFeeAmount,
          netAmount: netToSeller,
          paymentIntentId: paymentIntentId || null,
          paid: true,
          paidAt: now,
          paymentFailed: false,
          paymentFailureReason: null,
          shipped: false,
          trackingNumber: null,
          carrier: null,
          shippedAt: null,
        },
      }),
      prisma.listing.update({
        where: { id: String(listingId) },
        data: { status: "sold" },
      }),
    ]);

    res.status(201).json({ sale, purchase });
  } catch (err) {
    console.error("POST /purchases error:", err);
    res.status(500).json({ error: "Failed to create purchase." });
  }
});

// PATCH /purchases/:id/ship
app.patch("/purchases/:id/ship", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const { trackingNumber, carrier } = req.body || {};
  const shippedAt = new Date();

  try {
    const purchase = await prisma.purchase.update({
      where: { id: String(req.params.id) },
      data: {
        shipped: true,
        trackingNumber: trackingNumber || null,
        carrier: carrier || null,
        shippedAt,
      },
    });

    await prisma.sale.updateMany({
      where: {
        listingId: purchase.listingId,
        amount: purchase.amount,
      },
      data: {
        shipped: true,
        trackingNumber: trackingNumber || null,
        carrier: carrier || null,
        shippedAt,
      },
    });

    res.json(purchase);
  } catch (err) {
    console.error("PATCH /purchases/:id/ship error:", err);
    res.status(404).json({ error: "Purchase not found" });
  }
});

// Watchlist
app.post("/watchlist", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const { listingId } = req.body || {};

  if (!listingId) {
    return res.status(400).json({ error: "listingId is required" });
  }

  const listing = await prisma.listing.findUnique({
    where: { id: String(listingId) },
  });
  if (!listing) {
    return res.status(404).json({ error: "Listing not found" });
  }

  const existing = await prisma.watchlist.findUnique({
    where: {
      userId_listingId: {
        userId,
        listingId: String(listingId),
      },
    },
  });

  let watched = false;
  if (existing) {
    await prisma.watchlist.delete({
      where: { userId_listingId: { userId, listingId: String(listingId) } },
    });
    watched = false;
  } else {
    await prisma.watchlist.create({
      data: { userId, listingId: String(listingId) },
    });
    watched = true;
  }

  const watchCount = await prisma.watchlist.count({
    where: { listingId: String(listingId) },
  });
  await prisma.listing.update({
    where: { id: String(listingId) },
    data: { watchCount },
  });

  res.json({ watched, watchCount });
});

app.get("/me/watchlist", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const entries = await prisma.watchlist.findMany({
    where: { userId: myId },
    include: {
      listing: {
        select: {
          id: true,
          title: true,
          price: true,
          mainImage: true,
          status: true,
        },
      },
    },
    orderBy: { createdAt: "desc" },
  });

  const result = entries.map((w) => ({
    id: w.id,
    listingId: w.listingId,
    userId: w.userId,
    createdAt: w.createdAt,
    listing: w.listing
      ? {
          id: w.listing.id,
          title: w.listing.title,
          price: w.listing.price,
          mainImage: w.listing.mainImage || null,
          status: w.listing.status || "active",
        }
      : null,
  }));

  res.json(result);
});

// Offers
app.post("/offers", async (req, res) => {
  const buyerId = getUserIdForRequest(req);
  if (!buyerId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const { listingId, amount } = req.body || {};

  if (!listingId || typeof amount !== "number") {
    return res
      .status(400)
      .json({ error: "listingId and amount are required" });
  }
  if (amount <= 0) {
    return res.status(400).json({ error: "amount must be positive" });
  }

  try {
    const listing = await prisma.listing.findUnique({
      where: { id: String(listingId) },
    });
    if (!listing) {
      return res.status(404).json({ error: "Listing not found" });
    }
    if ((listing.status || "").toLowerCase() === "sold") {
      return res.status(400).json({ error: "Cannot offer on a sold listing" });
    }

    const offer = await prisma.offer.create({
      data: {
        listingId: String(listingId),
        buyerId,
        sellerId: listing.sellerId || null,
        amount: Number(amount),
        status: "pending",
      },
    });

    res.status(201).json(offer);
  } catch (err) {
    console.error("POST /offers error:", err);
    res.status(500).json({ error: "Failed to create offer" });
  }
});

app.get("/me/offers/buying", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const mine = await prisma.offer.findMany({
      where: { buyerId: myId },
      orderBy: { createdAt: "desc" },
    });
    res.json(mine);
  } catch (err) {
    console.error("GET /me/offers/buying error:", err);
    res.status(500).json({ error: "Failed to load offers." });
  }
});

app.get("/me/offers/selling", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const mine = await prisma.offer.findMany({
      where: { sellerId: myId },
      orderBy: { createdAt: "desc" },
    });
    res.json(mine);
  } catch (err) {
    console.error("GET /me/offers/selling error:", err);
    res.status(500).json({ error: "Failed to load offers." });
  }
});

app.patch("/offers/:id", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const offerId = req.params.id;
  const { status } = req.body || {};

  const allowedStatuses = ["accepted", "declined"];
  if (!allowedStatuses.includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  try {
    const offer = await prisma.offer.findUnique({ where: { id: offerId } });
    if (!offer) {
      return res.status(404).json({ error: "Offer not found" });
    }
    if (offer.sellerId && offer.sellerId !== myId) {
      return res
        .status(403)
        .json({ error: "Not allowed to modify this offer" });
    }

    const updated = await prisma.offer.update({
      where: { id: offerId },
      data: { status, updatedAt: new Date() },
    });

    res.json(updated);
  } catch (err) {
    console.error("PATCH /offers/:id error:", err);
    res.status(500).json({ error: "Failed to update offer" });
  }
});

// Seller Ratings
app.post("/ratings", async (req, res) => {
  const buyerId = getUserIdForRequest(req);
  const { listingId, score, comment } = req.body || {};

  if (!buyerId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (!listingId || typeof score !== "number") {
    return res
      .status(400)
      .json({ error: "listingId and score are required." });
  }

  const intScore = Math.round(score);
  if (intScore < 1 || intScore > 5) {
    return res.status(400).json({ error: "score must be between 1 and 5." });
  }

  try {
    const listing = await prisma.listing.findUnique({
      where: { id: String(listingId) },
    });
    if (!listing || !listing.sellerId) {
      return res.status(404).json({ error: "Listing not found." });
    }
    const sellerId = listing.sellerId;
    if (sellerId === buyerId) {
      return res.status(400).json({ error: "You can't rate yourself." });
    }

    const purchase = await prisma.purchase.findFirst({
      where: { listingId: String(listingId), buyerId },
    });
    if (!purchase) {
      return res.status(400).json({
        error: "You can only rate sellers for items you've purchased.",
      });
    }

    const existing = await prisma.rating.findFirst({
      where: { listingId: String(listingId), buyerId },
    });
    if (existing) {
      return res.status(400).json({ error: "You already rated this purchase." });
    }

    const rating = await prisma.rating.create({
      data: {
        listingId: String(listingId),
        sellerId,
        buyerId,
        score: intScore,
        comment: comment ? String(comment) : null,
      },
    });

    const seller = await prisma.user.update({
      where: { id: sellerId },
      data: {
        ratingCount: { increment: 1 },
        ratingTotal: { increment: intScore },
      },
    });

    if (seller.ratingCount + 1 > 0) {
      await prisma.user.update({
        where: { id: sellerId },
        data: {
          ratingAverage: (seller.ratingTotal + intScore) / (seller.ratingCount + 1),
        },
      });
    }

    res.status(201).json(rating);
  } catch (err) {
    console.error("POST /ratings error:", err);
    res.status(500).json({ error: "Could not submit rating." });
  }
});

app.get("/me/ratings/given", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const mine = await prisma.rating.findMany({
      where: { buyerId: myId },
      orderBy: { createdAt: "desc" },
    });
    res.json(mine);
  } catch (err) {
    console.error("GET /me/ratings/given error:", err);
    res.status(500).json({ error: "Failed to load ratings." });
  }
});

app.get("/me/ratings/received", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const mine = await prisma.rating.findMany({
      where: { sellerId: myId },
      orderBy: { createdAt: "desc" },
    });
    res.json(mine);
  } catch (err) {
    console.error("GET /me/ratings/received error:", err);
    res.status(500).json({ error: "Failed to load ratings." });
  }
});

app.get("/sellers/:id/ratings-summary", async (req, res) => {
  const sellerId = req.params.id;

  try {
    const seller = await prisma.user.findUnique({
      where: { id: sellerId },
      select: { id: true, ratingCount: true, ratingAverage: true },
    });
    if (!seller) {
      return res.status(404).json({ error: "Seller not found." });
    }

    res.json({
      sellerId,
      ratingCount: seller.ratingCount || 0,
      ratingAverage: seller.ratingAverage ?? null,
    });
  } catch (err) {
    console.error("GET /sellers/:id/ratings-summary error:", err);
    res.status(500).json({ error: "Failed to load ratings summary." });
  }
});

// My Garage summary
app.get("/me/garage", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const [myListings, mySales] = await Promise.all([
    prisma.listing.findMany({ where: { sellerId: myId } }),
    prisma.sale.findMany({ where: { sellerId: myId } }),
  ]);

  const activeListings = myListings.filter(
    (l) => (l.status || "active").toLowerCase() === "active"
  ).length;
  const soldListings = myListings.filter(
    (l) => (l.status || "").toLowerCase() === "sold"
  ).length;
  const totalListings = myListings.length;

  const now = Date.now();
  const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;

  let totalRevenue = 0;
  let last30DaysRevenue = 0;
  let soldCountLast30 = 0;

  for (const s of mySales) {
    const amt = s.amount || 0;
    totalRevenue += amt;
    const created = new Date(s.createdAt || 0).getTime();
    if (now - created <= thirtyDaysMs) {
      last30DaysRevenue += amt;
      soldCountLast30 += 1;
    }
  }

  const conversionRate =
    totalListings > 0 ? soldListings / totalListings : 0;
  const conversionRate30 =
    activeListings + soldCountLast30 > 0
      ? soldCountLast30 / (activeListings + soldCountLast30)
      : 0;

  const totals = {
    activeListings,
    soldListings,
    totalRevenue,
    last30DaysRevenue,
    totalListings,
    conversionRate,
    conversionRate30,
  };

  res.json({ totals, listings: myListings });
});

// Saved Searches
// Image search (text-based fallback until real vision search is added)
app.post("/image-search", async (req, res) => {
  try {
    const { imageUri, hintText, category, subcategory } = req.body || {};

    const trimmedHint = (hintText || "").toString().trim();
    const trimmedCategory = (category || "").toString().trim();
    const trimmedSubcategory = (subcategory || "").toString().trim();

    // Until a real vision service is wired, require a hint to search text.
    if (!trimmedHint) {
      return res.status(400).json({
        error:
          "Provide a short hint/keywords for now. Image similarity will be enabled once vision search is plugged in.",
      });
    }

    const where = buildListingFilter({
      query: trimmedHint,
      category: trimmedCategory || null,
      subcategory: trimmedSubcategory || null,
      minPrice: null,
      maxPrice: null,
      camera: "",
    });

    const listings = await prisma.listing.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: 20,
    });

    return res.json(listings);
  } catch (err) {
    console.error(
      "POST /image-search error:",
      err?.message || err,
      err?.stack || ""
    );
    return res.status(500).json({ error: "Failed to run image search." });
  }
});

// Categories helper
app.get("/categories", (req, res) => {
  res.json(categoryDefinitions);
});

app.post("/saved-searches", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const {
    name,
    query,
    category,
    subcategory,
    minPriceDollars,
    maxPriceDollars,
    notify,
    camera,
  } = req.body || {};

  const trimmedQuery = (query || "").toString().trim();
  const trimmedName = (name || "").toString().trim();
  const trimmedCamera = (camera || "").toString().trim();
  const trimmedSubcategory = (subcategory || "").toString().trim();
  const trimmedCategory = (category || "").toString().trim();

  // Basic guardrails to avoid DB errors or huge inputs
  const tooLong =
    trimmedName.length > 100 ||
    trimmedQuery.length > 200 ||
    trimmedSubcategory.length > 100 ||
    trimmedCategory.length > 100;
  if (tooLong) {
    return res.status(400).json({
      error: "Search name/query/category/subcategory is too long.",
    });
  }

  const toCents = (val) => {
    if (val == null) return null;
    const n = Number(val);
    if (Number.isNaN(n) || n < 0) return null;
    return Math.round(n * 100);
  };

  const minPrice = toCents(minPriceDollars);
  const maxPrice = toCents(maxPriceDollars);

  if (
    !trimmedQuery &&
    !trimmedCategory &&
    !trimmedSubcategory &&
    !trimmedCamera &&
    minPrice == null &&
    maxPrice == null
  ) {
    return res.status(400).json({
      error: "Provide at least a keyword, category, camera, or price range.",
    });
  }

  try {
    const savedSearch = await prisma.savedSearch.create({
      data: {
        userId,
        name: trimmedName || null,
        query: trimmedQuery || null,
        category: trimmedCategory || null,
        subcategory: trimmedSubcategory || null,
        minPrice,
        maxPrice,
        camera: trimmedCamera || null,
        notify: !!notify,
        lastCheckedAt: new Date(),
        lastListingCreatedAt: null,
      },
    });

    return res.json(savedSearch);
  } catch (err) {
    console.error(
      "POST /saved-searches error:",
      err?.message || err,
      err?.stack || ""
    );
    return res.status(500).json({ error: "Failed to save search." });
  }
});

app.get("/me/saved-searches", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const searches = await prisma.savedSearch.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
    });

    const now = new Date();
    const results = [];

    for (const s of searches) {
      const where = buildListingFilter({
        query: s.query || "",
        category: s.category,
        subcategory: s.subcategory,
        minPrice: s.minPrice,
        maxPrice: s.maxPrice,
        camera: s.camera || "",
      });

      const listings = await prisma.listing.findMany({
        where,
        orderBy: { createdAt: "desc" },
      });

      const comparer = s.lastListingCreatedAt || s.createdAt;
      const newCount = listings.filter(
        (l) => l.createdAt && new Date(l.createdAt) > new Date(comparer)
      ).length;

      const newestCreatedAt = listings.length ? listings[0].createdAt : null;

      const updated = await prisma.savedSearch.update({
        where: { id: s.id },
        data: {
          lastCheckedAt: now,
          lastListingCreatedAt: newestCreatedAt || s.lastListingCreatedAt,
        },
      });

      results.push({
        ...updated,
        newCount,
        checkedAt: now,
        newestListingCreatedAt: newestCreatedAt || s.lastListingCreatedAt,
      });
    }

    return res.json(results);
  } catch (err) {
    console.error(
      "GET /me/saved-searches error:",
      err?.message || err,
      err?.stack || ""
    );
    return res.status(500).json({ error: "Failed to load saved searches." });
  }
});

app.delete("/saved-searches/:id", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const id = req.params.id;

  try {
    await prisma.savedSearch.delete({
      where: { id },
    });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(404).json({ error: "Saved search not found." });
  }
});

// Push tokens + badge summary
app.post("/me/push-token", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const { expoPushToken } = req.body || {};

  if (!expoPushToken) {
    return res.status(400).json({ error: "expoPushToken is required." });
  }

  try {
    await prisma.pushToken.upsert({
      where: { expoPushToken },
      update: { userId, updatedAt: new Date() },
      create: { userId, expoPushToken, updatedAt: new Date() },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("POST /me/push-token error:", err);
    res.status(500).json({ error: "Failed to save push token." });
  }
});

app.get("/me/badges", async (req, res) => {
  const myId = getUserIdForRequest(req);
  if (!myId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const [
    shippingUnshipped,
    purchasesUnshipped,
    messagesNew,
    mySellingOffers,
    mySavedSearches,
  ] = await Promise.all([
    prisma.sale.count({ where: { sellerId: myId, shipped: false } }),
    prisma.purchase.count({ where: { buyerId: myId, shipped: false } }),
    prisma.message.count({ where: { toUserId: myId } }),
    prisma.offer.count({ where: { sellerId: myId, status: "pending" } }),
    prisma.savedSearch.count({ where: { userId: myId } }),
  ]);

  const myGarageAttention = shippingUnshipped + mySellingOffers;

  res.json({
    myGarageAttention,
    shippingUnshipped,
    purchasesUnshipped,
    messagesNew,
    savedSearchesNew: mySavedSearches,
  });
});

// Health check
app.get("/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ ok: true, db: true, time: new Date().toISOString() });
  } catch (err) {
    console.error("Health check error:", err);
    res
      .status(500)
      .json({ ok: false, db: false, error: err?.message || "db error" });
  }
});

// Lightweight analytics collector (best-effort, no DB write)
app.post("/analytics", analyticsLimiter, async (req, res) => {
  try {
    const { event, props, timestamp } = req.body || {};
    console.log("Analytics event:", {
      event,
      props,
      timestamp: timestamp || Date.now(),
      ip: req.ip,
      ua: req.headers["user-agent"],
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("Analytics handler error:", err);
    res.status(500).json({ error: "Analytics error" });
  }
});

// Cart endpoints (user-scoped)
app.get("/me/cart", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const items = await prisma.cartItem.findMany({
      where: { userId },
      include: { listing: true },
      orderBy: { createdAt: "desc" },
    });

    const payload = items.map((ci) => ({
      id: ci.id,
      listingId: ci.listingId,
      quantity: ci.quantity,
      listing: ci.listing,
    }));

    res.json(payload);
  } catch (err) {
    console.error("Cart fetch error:", err);
    res
      .status(500)
      .json({ error: err?.message || "Failed to load cart." });
  }
});

app.post("/me/cart", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const { listingId, quantity } = req.body || {};
    if (!listingId) {
      return res
        .status(400)
        .json({ error: "listingId is required" });
    }
    const qty =
      typeof quantity === "number"
        ? Math.max(1, Math.floor(quantity))
        : 1;

    const listing = await prisma.listing.findUnique({
      where: { id: listingId },
    });
    if (!listing) {
      return res.status(404).json({ error: "Listing not found" });
    }
    if ((listing.status || "").toLowerCase() === "sold") {
      return res
        .status(400)
        .json({ error: "Cannot add a sold listing to cart" });
    }

    const item = await prisma.cartItem.upsert({
      where: { userId_listingId: { userId, listingId } },
      update: { quantity: qty },
      create: { userId, listingId, quantity: qty },
      include: { listing: true },
    });

    res.json(item);
  } catch (err) {
    console.error("Cart add error:", err);
    res.status(500).json({ error: err?.message || "Cart add failed." });
  }
});

app.put("/me/cart/:listingId", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) return res.status(401).json({ error: "Unauthorized" });
  const { listingId } = req.params;
  const { quantity } = req.body || {};
  const qty =
    typeof quantity === "number" ? Math.max(1, Math.floor(quantity)) : 1;

  try {
    const item = await prisma.cartItem.update({
      where: { userId_listingId: { userId, listingId } },
      data: { quantity: qty },
      include: { listing: true },
    });
    res.json(item);
  } catch (err) {
    console.error("Cart update error:", err);
    res.status(500).json({ error: err?.message || "Cart update failed." });
  }
});

app.delete("/me/cart/:listingId", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) return res.status(401).json({ error: "Unauthorized" });
  const { listingId } = req.params;

  try {
    await prisma.cartItem.delete({
      where: { userId_listingId: { userId, listingId } },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("Cart delete error:", err);
    res
      .status(500)
      .json({ error: err?.message || "Cart delete failed." });
  }
});

app.delete("/me/cart", async (req, res) => {
  const userId = getUserIdForRequest(req);
  if (!userId) return res.status(401).json({ error: "Unauthorized" });
  try {
    await prisma.cartItem.deleteMany({ where: { userId } });
    res.json({ ok: true });
  } catch (err) {
    console.error("Cart clear error:", err);
    res.status(500).json({ error: "Could not clear cart." });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Powersports API listening on http://0.0.0.0:${PORT}`);
});
