const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");
const webpush = require("web-push");
const Razorpay = require("razorpay");
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});
/*
=========================================================
STYLESPOT FINAL BACKEND
PART 1 / 10
=========================================================

This file is intentionally divided into 10 parts.

IMPORTANT:
All API routes will run through ONE handleRequest()
function. This keeps req, res and URL scope correct.
=========================================================
*/

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

/*
=========================================================
BOOKING SETTINGS
=========================================================
*/

const SLOTS = [
  "09:00 AM",
  "09:30 AM",
  "10:00 AM",
  "10:30 AM",
  "11:00 AM",
  "11:30 AM",
  "12:00 PM",
  "12:30 PM",
  "01:00 PM",
  "01:30 PM",
  "02:00 PM",
  "02:30 PM",
  "03:00 PM",
  "03:30 PM",
  "04:00 PM",
  "04:30 PM",
  "05:00 PM",
  "05:30 PM",
  "06:00 PM",
  "06:30 PM",
  "07:00 PM",
  "07:30 PM",
  "08:00 PM",
  "08:30 PM"
];

const PENDING_TIMEOUT_MINUTES = 5;
const SLOT_CUTOFF_MINUTES = 10;

/*
=========================================================
PAYMENT / SERVICE HELPERS
=========================================================
*/

function parsePrice(text) {
  const match = String(text || "").match(/₹\s*([\d,.]+)/);

  if (!match) {
    return 0;
  }

  return Number(
    match[1].replace(/,/g, "")
  );
}

function cleanServiceName(text) {
  return String(text || "")
    .replace(/\s*—\s*₹[\d,.]+/i, "")
    .trim();
}

function normalizeServices(input) {
  let services = [];

  if (Array.isArray(input)) {
    services = input;
  } else if (input) {
    services = [input];
  }

  return services
    .map(service => {
      if (typeof service === "string") {
        return {
          name: cleanServiceName(service),
          price: parsePrice(service)
        };
      }

      return {
        name: cleanServiceName(
          service.name || service.service
        ),
        price: Number(service.price) || 0
      };
    })
    .filter(service => {
      return service.name && service.price >= 0;
    });
}

function calculateTotals(services) {
  const total = services.reduce(
    (sum, service) => {
      return sum + Number(service.price || 0);
    },
    0
  );

  const advance =
    Math.round(total * 0.20 * 100) / 100;

  const remaining =
    Math.round((total - advance) * 100) / 100;

  return {
    total,
    advance,
    remaining
  };
}

function servicesToText(services) {
  return services
    .map(service => {
      return `${service.name} — ₹${service.price}`;
    })
    .join(", ");
}

/*
=========================================================
INDIA DATE / TIME HELPERS
=========================================================
*/

function getIndiaParts() {
  const formatter = new Intl.DateTimeFormat(
    "en-CA",
    {
      timeZone: "Asia/Kolkata",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23"
    }
  );

  const parts =
    formatter.formatToParts(new Date());

  const get = type => {
    const part = parts.find(
      item => item.type === type
    );

    return part ? part.value : "";
  };

  return {
    date:
      `${get("year")}-${get("month")}-${get("day")}`,

    hour:
      Number(get("hour")),

    minute:
      Number(get("minute"))
  };
}

function slotToMinutes(slot) {
  const match = String(slot).match(
    /^(\d{1,2}):(\d{2})\s*(AM|PM)$/i
  );

  if (!match) {
    return -1;
  }

  let hour = Number(match[1]);
  const minute = Number(match[2]);
  const period = match[3].toUpperCase();

  if (period === "AM") {
    if (hour === 12) {
      hour = 0;
    }
  } else {
    if (hour !== 12) {
      hour += 12;
    }
  }

  return hour * 60 + minute;
}

function currentIndiaMinutes() {
  const now = getIndiaParts();

  return now.hour * 60 + now.minute;
}

function isSlotAvailableByTime(date, time) {
  const india = getIndiaParts();

  if (date > india.date) {
    return true;
  }

  if (date < india.date) {
    return false;
  }

  const slotMinutes = slotToMinutes(time);

  return (
    slotMinutes >
    currentIndiaMinutes() + SLOT_CUTOFF_MINUTES
  );
}

/*
=========================================================
PASSWORD HELPERS
=========================================================
*/

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt =
      crypto.randomBytes(16).toString("hex");

    crypto.scrypt(
      password,
      salt,
      64,
      (err, derivedKey) => {
        if (err) {
          return reject(err);
        }

        resolve(
          `${salt}:${derivedKey.toString("hex")}`
        );
      }
    );
  });
}

function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const parts =
      String(stored || "").split(":");

    if (parts.length !== 2) {
      return resolve(false);
    }

    const salt = parts[0];
    const key = parts[1];

    crypto.scrypt(
      password,
      salt,
      64,
      (err, derivedKey) => {
        if (err) {
          return reject(err);
        }

        const storedKey =
          Buffer.from(key, "hex");

        const valid =
          storedKey.length ===
            derivedKey.length &&
          crypto.timingSafeEqual(
            storedKey,
            derivedKey
          );

        resolve(valid);
      }
    );
  });
}

/*
=========================================================
AUTH TOKEN HELPER
=========================================================
*/

function getToken(req) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7);
}

/*
=========================================================
WEB PUSH CONFIGURATION
=========================================================
*/

let pushConfigured = false;

if (
  process.env.VAPID_PUBLIC_KEY &&
  process.env.VAPID_PRIVATE_KEY &&
  process.env.VAPID_EMAIL
) {
  try {
    webpush.setVapidDetails(
      process.env.VAPID_EMAIL,
      process.env.VAPID_PUBLIC_KEY,
      process.env.VAPID_PRIVATE_KEY
    );

    pushConfigured = true;

    console.log(
      "Web Push configured successfully."
    );
  } catch (err) {
    console.error(
      "Web Push configuration failed:",
      err.message
    );
  }
}

/*
=========================================================
END OF PART 1
=========================================================
*/
/*
=========================================================
DATABASE INITIALIZATION
PART 2 / 10
=========================================================
*/

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS barber_users (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id UUID REFERENCES users(id)
        ON DELETE CASCADE,
      barber_id UUID REFERENCES barber_users(id)
        ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS bookings (
      id UUID PRIMARY KEY,
      booking_no TEXT UNIQUE NOT NULL,

      user_id UUID REFERENCES users(id)
        ON DELETE SET NULL,

      name TEXT NOT NULL,
      phone TEXT NOT NULL,

      service TEXT NOT NULL,
      services_json JSONB DEFAULT '[]'::jsonb,

      total_amount NUMERIC(10,2) DEFAULT 0,
      advance_amount NUMERIC(10,2) DEFAULT 0,
      remaining_amount NUMERIC(10,2) DEFAULT 0,

      date DATE NOT NULL,
      time TEXT NOT NULL,
      notes TEXT DEFAULT '',

      status TEXT DEFAULT 'Pending',

      payment_status TEXT DEFAULT 'Unpaid',
      refund_status TEXT DEFAULT 'NotApplicable',

      pending_until TIMESTAMPTZ,
      accepted_at TIMESTAMPTZ,
      rejected_at TIMESTAMPTZ,
      expired_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      cancelled_at TIMESTAMPTZ,

      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id UUID PRIMARY KEY,

      booking_id UUID NOT NULL
        REFERENCES bookings(id)
        ON DELETE CASCADE,

      amount NUMERIC(10,2) NOT NULL,
      type TEXT NOT NULL DEFAULT 'Advance',

      status TEXT NOT NULL DEFAULT 'Pending',

      gateway TEXT DEFAULT '',
      gateway_payment_id TEXT DEFAULT '',
      gateway_order_id TEXT DEFAULT '',

      created_at TIMESTAMPTZ DEFAULT NOW(),
      verified_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id UUID PRIMARY KEY,

      user_id UUID REFERENCES users(id)
        ON DELETE CASCADE,

      barber_id UUID REFERENCES barber_users(id)
        ON DELETE CASCADE,

      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,

      booking_id UUID REFERENCES bookings(id)
        ON DELETE CASCADE,

      read BOOLEAN DEFAULT FALSE,

      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id UUID PRIMARY KEY,

      user_id UUID REFERENCES users(id)
        ON DELETE CASCADE,

      barber_id UUID REFERENCES barber_users(id)
        ON DELETE CASCADE,

      endpoint TEXT NOT NULL,
      subscription JSONB NOT NULL,

      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  /*
  =======================================================
  EXISTING DATABASE MIGRATIONS
  =======================================================
  */

  const migrations = [
    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS services_json
     JSONB DEFAULT '[]'::jsonb`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS total_amount
     NUMERIC(10,2) DEFAULT 0`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS advance_amount
     NUMERIC(10,2) DEFAULT 0`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS remaining_amount
     NUMERIC(10,2) DEFAULT 0`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS payment_status
     TEXT DEFAULT 'Unpaid'`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS refund_status
     TEXT DEFAULT 'NotApplicable'`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS pending_until
     TIMESTAMPTZ`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS accepted_at
     TIMESTAMPTZ`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS rejected_at
     TIMESTAMPTZ`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS expired_at
     TIMESTAMPTZ`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS completed_at
     TIMESTAMPTZ`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS cancelled_at
     TIMESTAMPTZ`,

    `ALTER TABLE bookings
     ADD COLUMN IF NOT EXISTS updated_at
     TIMESTAMPTZ DEFAULT NOW()`
  ];

  for (const sql of migrations) {
    await pool.query(sql);
  }

  /*
  =======================================================
  OLD STATUS MIGRATION
  =======================================================
  */

  await pool.query(`
    UPDATE bookings
    SET
      status = 'Pending',
      updated_at = NOW()
    WHERE status = 'Booked'
  `);

  /*
  =======================================================
  BARBER ACCOUNT FROM RENDER ENVIRONMENT VARIABLES
  =======================================================
  */

  if (
    process.env.BARBER_PHONE &&
    process.env.BARBER_PASSWORD
  ) {
    const existing =
      await pool.query(
        `SELECT id
         FROM barber_users
         WHERE phone = $1`,
        [process.env.BARBER_PHONE]
      );

    if (!existing.rows.length) {
      const id =
        crypto.randomUUID();

      const passwordHash =
        await hashPassword(
          process.env.BARBER_PASSWORD
        );

      await pool.query(
        `INSERT INTO barber_users
         (
           id,
           name,
           phone,
           password_hash
         )
         VALUES
         ($1,$2,$3,$4)`,
        [
          id,
          process.env.BARBER_NAME ||
            "StyleSpot Barber",
          process.env.BARBER_PHONE,
          passwordHash
        ]
      );

      console.log(
        "Barber account created from environment variables."
      );
    }
  }

  console.log("Database ready");
}

/*
=========================================================
END OF PART 2
=========================================================
*/
/*
=========================================================
RESPONSE + SESSION + NOTIFICATION HELPERS
PART 3 / 10
=========================================================
*/

/*
=========================================================
RESPONSE HELPER
=========================================================
*/

function send(
  res,
  code,
  data,
  type = "application/json"
) {
  res.writeHead(
    code,
    {
      "Content-Type": type,
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers":
        "Content-Type, Authorization",
      "Access-Control-Allow-Methods":
        "GET,POST,PATCH,DELETE,OPTIONS"
    }
  );

  res.end(
    type.includes("json")
      ? JSON.stringify(data)
      : data
  );
}

/*
=========================================================
REQUEST BODY HELPER
=========================================================
*/

function body(req) {
  return new Promise(
    (resolve, reject) => {
      let b = "";

      req.on(
        "data",
        chunk => {
          b += chunk;
        }
      );

      req.on(
        "end",
        () => {
          try {
            resolve(
              JSON.parse(b || "{}")
            );
          } catch {
            reject(
              new Error("Invalid JSON")
            );
          }
        }
      );

      req.on(
        "error",
        reject
      );
    }
  );
}

/*
=========================================================
CUSTOMER SESSION LOOKUP
=========================================================
*/

async function getCustomer(req) {
  const token =
    getToken(req);

  if (!token) {
    return null;
  }

  const result =
    await pool.query(
      `SELECT
         users.id,
         users.name,
         users.phone
       FROM sessions
       JOIN users
         ON users.id = sessions.user_id
       WHERE sessions.token = $1`,
      [token]
    );

  return (
    result.rows[0] ||
    null
  );
}

/*
=========================================================
BARBER SESSION LOOKUP
=========================================================
*/

async function getBarber(req) {
  const token =
    getToken(req);

  if (!token) {
    return null;
  }

  const result =
    await pool.query(
      `SELECT
         barber_users.id,
         barber_users.name,
         barber_users.phone
       FROM sessions
       JOIN barber_users
         ON barber_users.id = sessions.barber_id
       WHERE sessions.token = $1
       AND barber_users.active = TRUE`,
      [token]
    );

  return (
    result.rows[0] ||
    null
  );
}

/*
=========================================================
NOTIFICATION CREATION
=========================================================
*/

async function createNotification({
  userId = null,
  barberId = null,
  type,
  title,
  message,
  bookingId = null
}) {
  const id =
    crypto.randomUUID();

  await pool.query(
    `INSERT INTO notifications
     (
       id,
       user_id,
       barber_id,
       type,
       title,
       message,
       booking_id
     )
     VALUES
     ($1,$2,$3,$4,$5,$6,$7)`,
    [
      id,
      userId,
      barberId,
      type,
      title,
      message,
      bookingId
    ]
  );

  /*
  Browser push is optional.
  It becomes active only when all
  VAPID environment variables exist.
  */

  if (!pushConfigured) {
    return;
  }

  const result =
    await pool.query(
      `SELECT
         id,
         subscription
       FROM push_subscriptions
       WHERE
         (
           user_id = $1
           OR barber_id = $2
         )`,
      [
        userId,
        barberId
      ]
    );

  const payload =
    JSON.stringify({
      title,
      message,
      type,
      bookingId
    });

  for (
    const row of result.rows
  ) {
    try {
      await webpush.sendNotification(
        row.subscription,
        payload
      );
    } catch (err) {
      /*
      Remove expired/dead subscriptions.
      */

      if (
        err.statusCode === 404 ||
        err.statusCode === 410
      ) {
        await pool.query(
          `DELETE FROM push_subscriptions
           WHERE id = $1`,
          [row.id]
        );
      }
    }
  }
}

/*
=========================================================
EXPIRE PENDING BOOKINGS
=========================================================
*/

async function expirePendingBookings() {
  const result =
    await pool.query(
      `UPDATE bookings
       SET
         status = 'Expired',
         expired_at = NOW(),
         updated_at = NOW()
       WHERE status = 'Pending'
       AND pending_until IS NOT NULL
       AND pending_until <= NOW()
       RETURNING *`
    );

  for (
    const booking of result.rows
  ) {
    await createNotification({
      userId:
        booking.user_id,

      type:
        "booking_expired",

      title:
        "Booking Expired",

      message:
        `Your booking ${booking.booking_no} expired because the barber did not respond within 5 minutes.`,

      bookingId:
        booking.id
    });
  }

  if (result.rows.length) {
    console.log(
      `${result.rows.length} booking(s) expired.`
    );
  }
}

/*
=========================================================
EXPIRY WORKER
=========================================================
*/

setInterval(
  () => {
    expirePendingBookings()
      .catch(
        err => {
          console.error(
            "Expiry worker error:",
            err
          );
        }
      );
  },
  20000
);

/*
=========================================================
END OF PART 3
=========================================================
*/
/*
=========================================================
CUSTOMER SIGNUP
PART 4A / 10
=========================================================
*/

async function handleCustomerSignup(req, res) {
  const x = await body(req);

  const name =
    String(x.name || "").trim();

  const phone =
    String(x.phone || "").trim();

  const password =
    String(x.password || "");

  if (!name || !phone || !password) {
    return send(
      res,
      400,
      {
        error:
          "Name, phone and password are required"
      }
    );
  }

  if (password.length < 6) {
    return send(
      res,
      400,
      {
        error:
          "Password must be at least 6 characters"
      }
    );
  }

  const existing =
    await pool.query(
      `SELECT id
       FROM users
       WHERE phone = $1`,
      [phone]
    );

  if (existing.rows.length) {
    return send(
      res,
      409,
      {
        error:
          "An account with this phone number already exists"
      }
    );
  }

  const id =
    crypto.randomUUID();

  const passwordHash =
    await hashPassword(password);

  await pool.query(
    `INSERT INTO users
     (
       id,
       name,
       phone,
       password_hash
     )
     VALUES
     ($1,$2,$3,$4)`,
    [
      id,
      name,
      phone,
      passwordHash
    ]
  );

  return send(
    res,
    201,
    {
      message:
        "Account created successfully"
    }
  );
}

/*
=========================================================
END OF PART 4A
=========================================================
*/
/*
=========================================================
CUSTOMER LOGIN
PART 4B / 10
=========================================================
*/

async function handleCustomerLogin(req, res) {
  const x = await body(req);

  const phone =
    String(x.phone || "").trim();

  const password =
    String(x.password || "");

  if (!phone || !password) {
    return send(
      res,
      400,
      {
        error:
          "Phone and password are required"
      }
    );
  }

  const result =
    await pool.query(
      `SELECT
         id,
         name,
         phone,
         password_hash
       FROM users
       WHERE phone = $1`,
      [phone]
    );

  if (!result.rows.length) {
    return send(
      res,
      401,
      {
        error:
          "Invalid phone number or password"
      }
    );
  }

  const user =
    result.rows[0];

  const valid =
    await verifyPassword(
      password,
      user.password_hash
    );

  if (!valid) {
    return send(
      res,
      401,
      {
        error:
          "Invalid phone number or password"
      }
    );
  }

  const token =
    crypto
      .randomBytes(32)
      .toString("hex");

  await pool.query(
    `INSERT INTO sessions
     (
       token,
       user_id
     )
     VALUES
     ($1,$2)`,
    [
      token,
      user.id
    ]
  );

  return send(
    res,
    200,
    {
      message:
        "Login successful",

      token,

      user: {
        id:
          user.id,

        name:
          user.name,

        phone:
          user.phone
      }
    }
  );
}

/*
=========================================================
END OF PART 4B
=========================================================
*/
/*
=========================================================
CUSTOMER LOGOUT + CURRENT CUSTOMER
PART 4C / 10
=========================================================
*/

/*
=========================================================
CUSTOMER LOGOUT
=========================================================
*/

async function handleCustomerLogout(req, res) {
  const token =
    getToken(req);

  if (token) {
    await pool.query(
      `DELETE FROM sessions
       WHERE token = $1`,
      [token]
    );
  }

  return send(
    res,
    200,
    {
      message:
        "Logged out successfully"
    }
  );
}

/*
=========================================================
CURRENT CUSTOMER
=========================================================
*/

async function handleCustomerMe(req, res) {
  const customer =
    await getCustomer(req);

  if (!customer) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  return send(
    res,
    200,
    {
      user:
        customer
    }
  );
}

/*
=========================================================
END OF PART 4C
=========================================================
*/
/*
=========================================================
BARBER LOGIN
PART 4D / 10
=========================================================
*/

async function handleBarberLogin(req, res) {
  const x = await body(req);

  const phone =
    String(x.phone || "").trim();

  const password =
    String(x.password || "");

  if (!phone || !password) {
    return send(
      res,
      400,
      {
        error:
          "Phone and password are required"
      }
    );
  }

  const result =
    await pool.query(
      `SELECT
         id,
         name,
         phone,
         password_hash,
         active
       FROM barber_users
       WHERE phone = $1`,
      [phone]
    );

  if (!result.rows.length) {
    return send(
      res,
      401,
      {
        error:
          "Invalid barber credentials"
      }
    );
  }

  const barber =
    result.rows[0];

  if (!barber.active) {
    return send(
      res,
      403,
      {
        error:
          "Barber account is inactive"
      }
    );
  }

  const valid =
    await verifyPassword(
      password,
      barber.password_hash
    );

  if (!valid) {
    return send(
      res,
      401,
      {
        error:
          "Invalid barber credentials"
      }
    );
  }

  const token =
    crypto
      .randomBytes(32)
      .toString("hex");

  await pool.query(
    `INSERT INTO sessions
     (
       token,
       barber_id
     )
     VALUES
     ($1,$2)`,
    [
      token,
      barber.id
    ]
  );

  return send(
    res,
    200,
    {
      message:
        "Barber login successful",

      token,

      barber: {
        id:
          barber.id,

        name:
          barber.name,

        phone:
          barber.phone
      }
    }
  );
}

/*
=========================================================
END OF PART 4D
=========================================================
*/
/*
=========================================================
BARBER LOGOUT + CURRENT BARBER
PART 4E / 10
=========================================================
*/

/*
=========================================================
BARBER LOGOUT
=========================================================
*/

async function handleBarberLogout(req, res) {
  const token =
    getToken(req);

  if (token) {
    await pool.query(
      `DELETE FROM sessions
       WHERE token = $1`,
      [token]
    );
  }

  return send(
    res,
    200,
    {
      message:
        "Barber logged out successfully"
    }
  );
}

/*
=========================================================
CURRENT BARBER
=========================================================
*/

async function handleBarberMe(req, res) {
  const barber =
    await getBarber(req);

  if (!barber) {
    return send(
      res,
      401,
      {
        error:
          "Barber authentication required"
      }
    );
  }

  return send(
    res,
    200,
    {
      barber:
        barber
    }
  );
}

/*
=========================================================
END OF PART 4E
=========================================================
*/
/*
=========================================================
BOOKING SYSTEM
PART 5 / 10
=========================================================
*/

/*
=========================================================
AVAILABLE BOOKING SLOTS
=========================================================
*/

async function handleAvailableSlots(req, res, u) {
  const date =
    String(
      u.searchParams.get("date") || ""
    ).trim();

  if (!date) {
    return send(
      res,
      400,
      {
        error:
          "Date is required"
      }
    );
  }

  const bookings =
    await pool.query(
      `SELECT time
       FROM bookings
       WHERE date = $1
       AND status IN
         (
           'Pending',
           'AwaitingPayment',
           'Confirmed',
           'Accepted'
         )`,
      [date]
    );

  const bookedTimes =
    bookings.rows.map(
      row => row.time
    );

  const available =
    SLOTS.filter(
      time =>
        !bookedTimes.includes(time) &&
        isSlotAvailableByTime(
          date,
          time
        )
    );

  return send(
    res,
    200,
    {
      date,
      slots:
        available
    }
  );
}

/*
=========================================================
CUSTOMER CREATE BOOKING
=========================================================
*/

async function handleCreateBooking(req, res) {
  const customer =
    await getCustomer(req);

  if (!customer) {
    return send(
      res,
      401,
      {
        error:
          "Please login before booking"
      }
    );
  }

  const x =
    await body(req);

  const name =
    String(
      x.name ||
      customer.name ||
      ""
    ).trim();

  const phone =
    String(
      x.phone ||
      customer.phone ||
      ""
    ).trim();

  const date =
    String(
      x.date || ""
    ).trim();

  const time =
    String(
      x.time || ""
    ).trim();

  const notes =
    String(
      x.notes || ""
    ).trim();

  const services =
    normalizeServices(
      x.services ||
      x.service
    );

  if (
    !name ||
    !phone ||
    !date ||
    !time ||
    !services.length
  ) {
    return send(
      res,
      400,
      {
        error:
          "Name, phone, service, date and time are required"
      }
    );
  }

  if (!SLOTS.includes(time)) {
    return send(
      res,
      400,
      {
        error:
          "Invalid time slot"
      }
    );
  }

  if (
    !isSlotAvailableByTime(
      date,
      time
    )
  ) {
    return send(
      res,
      400,
      {
        error:
          "This time slot is no longer available"
      }
    );
  }

  const totals =
    calculateTotals(
      services
    );

  if (totals.total <= 0) {
    return send(
      res,
      400,
      {
        error:
          "Booking total must be greater than zero"
      }
    );
  }

  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    /*
    =====================================================
    SLOT LOCK
    =====================================================

    This prevents two customers from booking
    the same date/time simultaneously.
    */

    await client.query(
      `SELECT pg_advisory_xact_lock(
         hashtext($1)
       )`,
      [
        `${date}|${time}`
      ]
    );

    const existing =
      await client.query(
        `SELECT id
         FROM bookings
         WHERE date = $1
         AND time = $2
         AND status IN
           (
             'Pending',
             'AwaitingPayment',
             'Confirmed',
             'Accepted'
           )
         LIMIT 1`,
        [
          date,
          time
        ]
      );

    if (existing.rows.length) {
      await client.query(
        "ROLLBACK"
      );

      return send(
        res,
        409,
        {
          error:
            "This slot has just been booked. Please choose another slot."
        }
      );
    }

    const id =
      crypto.randomUUID();

    const bookingNo =
      "SS-" +
      Math.floor(
        100000 +
        Math.random() * 900000
      );

    const pendingUntil =
      new Date(
        Date.now() +
        PENDING_TIMEOUT_MINUTES *
        60 *
        1000
      );

    await client.query(
      `INSERT INTO bookings
       (
         id,
         booking_no,
         user_id,
         name,
         phone,
         service,
         services_json,
         total_amount,
         advance_amount,
         remaining_amount,
         date,
         time,
         notes,
         status,
         payment_status,
         refund_status,
         pending_until
       )
       VALUES
       (
         $1,
         $2,
         $3,
         $4,
         $5,
         $6,
         $7,
         $8,
         $9,
         $10,
         $11,
         $12,
         $13,
         'Pending',
         'Unpaid',
         'NotApplicable',
         $14
       )`,
      [
        id,
        bookingNo,
        customer.id,
        name,
        phone,
        servicesToText(
          services
        ),
        JSON.stringify(
          services
        ),
        totals.total,
        totals.advance,
        totals.remaining,
        date,
        time,
        notes,
        pendingUntil
      ]
    );

    await client.query(
      "COMMIT"
    );

    /*
    =====================================================
    NOTIFY ACTIVE BARBERS
    =====================================================
    */

    const barbers =
      await pool.query(
        `SELECT id
         FROM barber_users
         WHERE active = TRUE`
      );

    for (
      const barber of barbers.rows
    ) {
      await createNotification({
        barberId:
          barber.id,

        type:
          "new_booking",

        title:
          "New Booking Request",

        message:
          `${name} requested ${servicesToText(services)} on ${date} at ${time}.`,

        bookingId:
          id
      });
    }

    return send(
      res,
      201,
      {
        message:
          "Booking request sent",

        booking: {
          id,
          bookingNo,
          name,
          phone,
          services,

          totalAmount:
            totals.total,

          advanceAmount:
            totals.advance,

          remainingAmount:
            totals.remaining,

          date,
          time,
          notes,

          status:
            "Pending",

          paymentStatus:
            "Unpaid",

          refundStatus:
            "NotApplicable",

          pendingUntil
        }
      }
    );

  } catch (err) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    throw err;

  } finally {
    client.release();
  }
}

/*
=========================================================
CUSTOMER MY BOOKINGS
=========================================================
*/

async function handleMyBookings(req, res) {
  const customer =
    await getCustomer(req);

  if (!customer) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  await expirePendingBookings();

  const result =
    await pool.query(
      `SELECT
         id,
         booking_no,
         user_id,
         name,
         phone,
         service,
         services_json,
         total_amount,
         advance_amount,
         remaining_amount,
         date,
         time,
         notes,
         status,
         payment_status,
         refund_status,
         pending_until,
         accepted_at,
         rejected_at,
         expired_at,
         completed_at,
         cancelled_at,
         created_at,
         updated_at
       FROM bookings
       WHERE user_id = $1
       ORDER BY
         created_at DESC`,
      [
        customer.id
      ]
    );

  return send(
    res,
    200,
    {
      bookings:
        result.rows
    }
  );
}

/*
=========================================================
END OF PART 5
=========================================================
*/
/*
=========================================================
BARBER DASHBOARD + BOOKING ACTIONS
PART 6 / 10
=========================================================
*/

/*
=========================================================
BARBER DASHBOARD
=========================================================
*/

async function handleBarberBookings(req, res) {
  const barber =
    await getBarber(req);

  if (!barber) {
    return send(
      res,
      401,
      {
        error:
          "Barber authentication required"
      }
    );
  }

  await expirePendingBookings();

  const result =
    await pool.query(
      `SELECT
         b.id,
         b.booking_no,
         b.user_id,
         b.name,
         b.phone,
         b.service,
         b.services_json,
         b.total_amount,
         b.advance_amount,
         b.remaining_amount,
         b.date,
         b.time,
         b.notes,
         b.status,
         b.payment_status,
         b.refund_status,
         b.pending_until,
         b.accepted_at,
         b.rejected_at,
         b.expired_at,
         b.completed_at,
         b.cancelled_at,
         b.created_at,
         b.updated_at
       FROM bookings b
       ORDER BY
         b.date ASC,
         b.time ASC,
         b.created_at DESC`
    );

  return send(
    res,
    200,
    {
      bookings:
        result.rows
    }
  );
}

/*
=========================================================
BARBER ACCEPT BOOKING
=========================================================
*/

async function handleBarberAcceptBooking(
  req,
  res,
  bookingId
) {
  const barber =
    await getBarber(req);

  if (!barber) {
    return send(
      res,
      401,
      {
        error:
          "Barber authentication required"
      }
    );
  }

  if (!bookingId) {
    return send(
      res,
      400,
      {
        error:
          "Booking ID is required"
      }
    );
  }

  /*
  Expire old pending bookings before
  attempting to accept this one.
  */

  await expirePendingBookings();

  const result =
    await pool.query(
      `UPDATE bookings
       SET
         status = 'AwaitingPayment',
         accepted_at = NOW(),
         updated_at = NOW()
       WHERE id = $1
       AND status = 'Pending'
       AND pending_until > NOW()
       RETURNING *`,
      [
        bookingId
      ]
    );

  if (!result.rows.length) {
    return send(
      res,
      409,
      {
        error:
          "Booking cannot be accepted. It may have expired or already been processed."
      }
    );
  }

  const booking =
    result.rows[0];

  await createNotification({
    userId:
      booking.user_id,

    type:
      "booking_accepted",

    title:
      "Booking Accepted",

    message:
      `Your booking ${booking.booking_no} has been accepted. Please complete the advance payment.`,

    bookingId:
      booking.id
  });

  return send(
    res,
    200,
    {
      message:
        "Booking accepted",

      booking
    }
  );
}

/*
=========================================================
BARBER REJECT BOOKING
=========================================================
*/

async function handleBarberRejectBooking(
  req,
  res,
  bookingId
) {
  const barber =
    await getBarber(req);

  if (!barber) {
    return send(
      res,
      401,
      {
        error:
          "Barber authentication required"
      }
    );
  }

  if (!bookingId) {
    return send(
      res,
      400,
      {
        error:
          "Booking ID is required"
      }
    );
  }

  const result =
    await pool.query(
      `UPDATE bookings
       SET
         status = 'Cancelled',
         rejected_at = NOW(),
         cancelled_at = NOW(),
         updated_at = NOW()
       WHERE id = $1
       AND status = 'Pending'
       RETURNING *`,
      [
        bookingId
      ]
    );

  if (!result.rows.length) {
    return send(
      res,
      409,
      {
        error:
          "Booking cannot be rejected. It may have already been processed."
      }
    );
  }

  const booking =
    result.rows[0];

  await createNotification({
    userId:
      booking.user_id,

    type:
      "booking_rejected",

    title:
      "Booking Rejected",

    message:
      `Your booking ${booking.booking_no} was rejected by the barber.`,

    bookingId:
      booking.id
  });

  return send(
    res,
    200,
    {
      message:
        "Booking rejected",

      booking
    }
  );
}

/*
=========================================================
END OF PART 6
=========================================================
*/
/*
=========================================================
CUSTOMER PAYMENT SYSTEM
PART 7 / 10
=========================================================
*/

/*
=========================================================
CREATE ADVANCE PAYMENT
=========================================================
*/
  
async function handleCreatePayment(
  req,
  res
) {
  const customer =
    await getCustomer(req);

  if (!customer) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  const x =
    await body(req);

  const bookingId =
    String(
      x.bookingId || ""
    ).trim();

  if (!bookingId) {
    return send(
      res,
      400,
      {
        error:
          "Booking ID is required"
      }
    );
  }

  const result =
    await pool.query(
      `SELECT
         id,
         booking_no,
         user_id,
         total_amount,
         advance_amount,
         remaining_amount,
         status,
         payment_status
       FROM bookings
       WHERE id = $1
       AND user_id = $2`,
      [
        bookingId,
        customer.id
      ]
    );

  if (!result.rows.length) {
    return send(
      res,
      404,
      {
        error:
          "Booking not found"
      }
    );
  }

  const booking =
    result.rows[0];

  if (
    booking.status !==
    "AwaitingPayment"
  ) {
    return send(
      res,
      409,
      {
        error:
          "This booking is not awaiting payment"
      }
    );
  }

  if (
    booking.payment_status ===
    "Paid"
  ) {
    return send(
      res,
      409,
      {
        error:
          "Advance payment has already been completed"
      }
    );
  }

  /*
  =======================================================
  PREVENT DUPLICATE PENDING PAYMENTS
  =======================================================
  */

  const pendingPayment =
    await pool.query(
      `SELECT
         id,
         amount,
         type,
         status,
         gateway,
         gateway_order_id
       FROM payments
       WHERE booking_id = $1
       AND status = 'Pending'
       ORDER BY created_at DESC
       LIMIT 1`,
      [
        booking.id
      ]
    );

  if (pendingPayment.rows.length) {
    const existing =
      pendingPayment.rows[0];

    return send(
      res,
      200,
      {
        message:
          "Pending payment already exists",

        payment: {
          id:
            existing.id,

          bookingId:
            booking.id,

          bookingNo:
            booking.booking_no,

          amount:
            Number(
              existing.amount
            ),

          type:
            existing.type,

          status:
            existing.status,

          gateway:
            existing.gateway,

          gatewayOrderId:
            existing.gateway_order_id
        }
      }
    );
  }

  /*
  =======================================================
  CREATE RAZORPAY ORDER
  =======================================================
  */

  const paymentId =
    crypto.randomUUID();

  const advanceAmount =
    Number(
      booking.advance_amount
    );

  const amountInPaise =
    Math.round(
      advanceAmount * 100
    );

  if (
    !Number.isFinite(
      amountInPaise
    ) ||
    amountInPaise < 100
  ) {
    return send(
      res,
      400,
      {
        error:
          "Invalid advance payment amount"
      }
    );
  }

  let razorpayOrder;

  try {
    razorpayOrder =
      await razorpay.orders.create({
        amount:
          amountInPaise,

        currency:
          "INR",

        receipt:
          `SP${paymentId.replace(/-/g, "")}`,

        notes: {
          booking_id:
            booking.id,

          booking_no:
            booking.booking_no
        }
      });
  } catch (error) {
    console.error(
      "Razorpay order creation failed:",
      error
    );

    return send(
      res,
      500,
      {
        error:
          "Unable to create payment order"
      }
    );
  }

  /*
  =======================================================
  SAVE PAYMENT RECORD
  =======================================================
  */

  await pool.query(
    `INSERT INTO payments
     (
       id,
       booking_id,
       amount,
       type,
       status,
       gateway,
       gateway_order_id
     )
     VALUES
     (
       $1,
       $2,
       $3,
       'Advance',
       'Pending',
       'Razorpay',
       $4
     )`,
    [
      paymentId,
      booking.id,
      advanceAmount,
      razorpayOrder.id
    ]
  );

  return send(
    res,
    201,
    {
      message:
        "Razorpay payment order created",

      payment: {
        id:
          paymentId,

        bookingId:
          booking.id,

        bookingNo:
          booking.booking_no,

        amount:
          advanceAmount,

        amountInPaise:
          amountInPaise,

        type:
          "Advance",

        status:
          "Pending",

        gateway:
          "Razorpay",

        gatewayOrderId:
          razorpayOrder.id,

        keyId:
          process.env.RAZORPAY_KEY_ID
      }
    }
  );
}
/*
=========================================================
PAYMENT VERIFICATION
=========================================================
*/

async function handleVerifyPayment(
  req,
  res
) {
  const customer =
    await getCustomer(req);

  if (!customer) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  const x =
    await body(req);

  const paymentId =
    String(
      x.paymentId || ""
    ).trim();

  const razorpayPaymentId =
    String(
      x.razorpayPaymentId || ""
    ).trim();

  const razorpaySignature =
    String(
      x.razorpaySignature || ""
    ).trim();

  if (
    !paymentId ||
    !razorpayPaymentId ||
    !razorpaySignature
  ) {
    return send(
      res,
      400,
      {
        error:
          "Payment verification details are required"
      }
    );
  }

  const result =
    await pool.query(
      `SELECT
         p.*,
         b.booking_no,
         b.user_id,
         b.status AS booking_status,
         b.payment_status AS booking_payment_status
       FROM payments p
       JOIN bookings b
         ON b.id = p.booking_id
       WHERE p.id = $1
       AND b.user_id = $2`,
      [
        paymentId,
        customer.id
      ]
    );

  if (!result.rows.length) {
    return send(
      res,
      404,
      {
        error:
          "Payment not found"
      }
    );
  }

  const payment =
    result.rows[0];

  if (
    payment.status ===
    "Verified"
  ) {
    return send(
      res,
      200,
      {
        message:
          "Payment already verified",

        payment
      }
    );
  }

  if (
    payment.status !==
    "Pending"
  ) {
    return send(
      res,
      409,
      {
        error:
          "Payment cannot be verified in its current status"
      }
    );
  }

  if (
    !payment.gateway_order_id
  ) {
    return send(
      res,
      400,
      {
        error:
          "Razorpay order ID is missing"
      }
    );
  }

  if (
    !process.env.RAZORPAY_KEY_SECRET
  ) {
    console.error(
      "RAZORPAY_KEY_SECRET is missing"
    );

    return send(
      res,
      500,
      {
        error:
          "Payment verification is not configured"
      }
    );
  }

  /*
  =======================================================
  VERIFY RAZORPAY SIGNATURE
  =======================================================
  */

  const signatureBody =
    payment.gateway_order_id +
    "|" +
    razorpayPaymentId;

  const expectedSignature =
    crypto
      .createHmac(
        "sha256",
        process.env.RAZORPAY_KEY_SECRET
      )
      .update(signatureBody)
      .digest("hex");

  let signatureValid = false;

  try {

    const expectedBuffer =
      Buffer.from(
        expectedSignature,
        "hex"
      );

    const receivedBuffer =
      Buffer.from(
        razorpaySignature,
        "hex"
      );

    if (
      expectedBuffer.length ===
      receivedBuffer.length
    ) {
      signatureValid =
        crypto.timingSafeEqual(
          expectedBuffer,
          receivedBuffer
        );
    }

  } catch (error) {

    signatureValid = false;

  }

  if (!signatureValid) {

    return send(
      res,
      400,
      {
        error:
          "Payment signature verification failed"
      }
    );
  }

  /*
  =======================================================
  PAYMENT VERIFIED
  =======================================================
  */

  const updateResult =
    await pool.query(
      `UPDATE payments
       SET
         status = 'Verified',
         gateway_payment_id = $1,
         verified_at = NOW()
       WHERE id = $2
       AND status = 'Pending'
       RETURNING *`,
      [
        razorpayPaymentId,
        payment.id
      ]
    );

  if (!updateResult.rows.length) {
    return send(
      res,
      409,
      {
        error:
          "Payment was already processed"
      }
    );
  }

  /*
  =======================================================
  CONFIRM BOOKING
  =======================================================
  */

  const bookingResult =
    await pool.query(
      `UPDATE bookings
       SET
         status = 'Confirmed',
         payment_status = 'Paid',
         updated_at = NOW()
       WHERE id = $1
       AND user_id = $2
       AND status = 'AwaitingPayment'
       AND payment_status <> 'Paid'
       RETURNING *`,
      [
        payment.booking_id,
        customer.id
      ]
    );

  if (!bookingResult.rows.length) {

    return send(
      res,
      409,
      {
        error:
          "Payment verified but booking could not be confirmed"
      }
    );
  }

  const booking =
    bookingResult.rows[0];

  await createNotification({
    userId:
      booking.user_id,

    type:
      "payment_success",

    title:
      "Payment Successful",

    message:
      `Advance payment received for booking ${booking.booking_no}. Your booking is confirmed.`,

    bookingId:
      booking.id
  });

  return send(
    res,
    200,
    {
      message:
        "Payment verified and booking confirmed",

      payment:
        updateResult.rows[0],

      booking
    }
  );
}

/*
=========================================================
PAYMENT STATUS
=========================================================
*/

async function handlePaymentStatus(
  req,
  res,
  u
) {
  const customer =
    await getCustomer(req);

  if (!customer) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  const paymentId =
    String(
      u.searchParams.get(
        "paymentId"
      ) || ""
    ).trim();

  if (!paymentId) {
    return send(
      res,
      400,
      {
        error:
          "Payment ID is required"
      }
    );
  }

  const result =
    await pool.query(
      `SELECT
         p.id,
         p.booking_id,
         p.amount,
         p.type,
         p.status,
         p.gateway,
         p.gateway_payment_id,
         p.gateway_order_id,
         p.created_at,
         p.verified_at,
         b.booking_no,
         b.status AS booking_status,
         b.payment_status AS booking_payment_status
       FROM payments p
       JOIN bookings b
         ON b.id = p.booking_id
       WHERE p.id = $1
       AND b.user_id = $2`,
      [
        paymentId,
        customer.id
      ]
    );

  if (!result.rows.length) {
    return send(
      res,
      404,
      {
        error:
          "Payment not found"
      }
    );
  }

  const payment =
    result.rows[0];

  return send(
    res,
    200,
    {
      payment
    }
  );
}

/*
=========================================================
END OF PART 7
=========================================================
*/
/*
=========================================================
BOOKING STATUS ACTIONS
PART 8 / 10
=========================================================
*/

/*
=========================================================
BARBER COMPLETE BOOKING
=========================================================
*/

async function handleBarberCompleteBooking(
  req,
  res,
  bookingId
) {
  const barber =
    await getBarber(req);

  if (!barber) {
    return send(
      res,
      401,
      {
        error:
          "Barber authentication required"
      }
    );
  }

  if (!bookingId) {
    return send(
      res,
      400,
      {
        error:
          "Booking ID is required"
      }
    );
  }

  const result =
    await pool.query(
      `UPDATE bookings
       SET
         status = 'Completed',
         completed_at = NOW(),
         updated_at = NOW()
       WHERE id = $1
       AND status IN
         (
           'Confirmed',
           'Accepted'
         )
       RETURNING *`,
      [
        bookingId
      ]
    );

  if (!result.rows.length) {
    return send(
      res,
      409,
      {
        error:
          "Booking cannot be completed in its current status"
      }
    );
  }

  const booking =
    result.rows[0];

  await createNotification({
    userId:
      booking.user_id,

    type:
      "booking_completed",

    title:
      "Booking Completed",

    message:
      `Your booking ${booking.booking_no} has been marked as completed.`,

    bookingId:
      booking.id
  });

  return send(
    res,
    200,
    {
      message:
        "Booking marked as completed",

      booking
    }
  );
}

/*
=========================================================
BARBER CANCEL BOOKING
=========================================================
*/

async function handleBarberCancelBooking(
  req,
  res,
  bookingId
) {
  const barber =
    await getBarber(req);

  if (!barber) {
    return send(
      res,
      401,
      {
        error:
          "Barber authentication required"
      }
    );
  }

  if (!bookingId) {
    return send(
      res,
      400,
      {
        error:
          "Booking ID is required"
      }
    );
  }

  const result =
    await pool.query(
      `UPDATE bookings
       SET
         status = 'Cancelled',
         cancelled_at = NOW(),
         updated_at = NOW()
       WHERE id = $1
       AND status IN
         (
           'Confirmed',
           'Accepted',
           'AwaitingPayment'
         )
       RETURNING *`,
      [
        bookingId
      ]
    );

  if (!result.rows.length) {
    return send(
      res,
      409,
      {
        error:
          "Booking cannot be cancelled in its current status"
      }
    );
  }

  const booking =
    result.rows[0];

  await createNotification({
    userId:
      booking.user_id,

    type:
      "booking_cancelled",

    title:
      "Booking Cancelled",

    message:
      `Your booking ${booking.booking_no} has been cancelled by the barber.`,

    bookingId:
      booking.id
  });

  return send(
    res,
    200,
    {
      message:
        "Booking cancelled",

      booking
    }
  );
}

/*
=========================================================
CUSTOMER CANCEL BOOKING
=========================================================
*/

async function handleCustomerCancelBooking(
  req,
  res,
  bookingId
) {
  const customer =
    await getCustomer(req);

  if (!customer) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  if (!bookingId) {
    return send(
      res,
      400,
      {
        error:
          "Booking ID is required"
      }
    );
  }

  const result =
    await pool.query(
      `UPDATE bookings
       SET
         status = 'Cancelled',
         cancelled_at = NOW(),
         updated_at = NOW()
       WHERE id = $1
       AND user_id = $2
       AND status IN
         (
           'Pending',
           'AwaitingPayment',
           'Confirmed',
           'Accepted'
         )
       RETURNING *`,
      [
        bookingId,
        customer.id
      ]
    );

  if (!result.rows.length) {
    return send(
      res,
      409,
      {
        error:
          "Booking cannot be cancelled in its current status"
      }
    );
  }

  const booking =
    result.rows[0];

  /*
  =======================================================
  NOTIFY ACTIVE BARBERS
  =======================================================
  */

  const barbers =
    await pool.query(
      `SELECT id
       FROM barber_users
       WHERE active = TRUE`
    );

  for (
    const barber of barbers.rows
  ) {
    await createNotification({
      barberId:
        barber.id,

      type:
        "customer_cancelled",

      title:
        "Booking Cancelled",

      message:
        `${booking.name} cancelled booking ${booking.booking_no}.`,

      bookingId:
        booking.id
    });
  }

  return send(
    res,
    200,
    {
      message:
        "Booking cancelled successfully",

      booking
    }
  );
}

/*
=========================================================
END OF PART 8
=========================================================
*/
/*
=========================================================
NOTIFICATIONS + PUSH SUBSCRIPTIONS
PART 9 / 10
=========================================================
*/

/*
=========================================================
GET NOTIFICATIONS
=========================================================
*/

async function handleGetNotifications(
  req,
  res
) {
  const customer =
    await getCustomer(req);

  const barber =
    customer
      ? null
      : await getBarber(req);

  if (!customer && !barber) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  const result =
    await pool.query(
      `SELECT
         id,
         type,
         title,
         message,
         booking_id,
         read,
         created_at
       FROM notifications
       WHERE
         (
           user_id = $1
           OR barber_id = $2
         )
       ORDER BY
         created_at DESC
       LIMIT 100`,
      [
        customer?.id || null,
        barber?.id || null
      ]
    );

  return send(
    res,
    200,
    {
      notifications:
        result.rows
    }
  );
}

/*
=========================================================
MARK ONE NOTIFICATION AS READ
=========================================================
*/

async function handleMarkNotificationRead(
  req,
  res,
  notificationId
) {
  const customer =
    await getCustomer(req);

  const barber =
    customer
      ? null
      : await getBarber(req);

  if (!customer && !barber) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  if (!notificationId) {
    return send(
      res,
      400,
      {
        error:
          "Notification ID is required"
      }
    );
  }

  const result =
    await pool.query(
      `UPDATE notifications
       SET read = TRUE
       WHERE id = $1
       AND
       (
         user_id = $2
         OR barber_id = $3
       )
       RETURNING *`,
      [
        notificationId,
        customer?.id || null,
        barber?.id || null
      ]
    );

  if (!result.rows.length) {
    return send(
      res,
      404,
      {
        error:
          "Notification not found"
      }
    );
  }

  return send(
    res,
    200,
    {
      message:
        "Notification marked as read",

      notification:
        result.rows[0]
    }
  );
}

/*
=========================================================
MARK ALL NOTIFICATIONS AS READ
=========================================================
*/

async function handleMarkAllNotificationsRead(
  req,
  res
) {
  const customer =
    await getCustomer(req);

  const barber =
    customer
      ? null
      : await getBarber(req);

  if (!customer && !barber) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  await pool.query(
    `UPDATE notifications
     SET read = TRUE
     WHERE
       user_id = $1
       OR barber_id = $2`,
    [
      customer?.id || null,
      barber?.id || null
    ]
  );

  return send(
    res,
    200,
    {
      message:
        "All notifications marked as read"
    }
  );
}

/*
=========================================================
SAVE PUSH SUBSCRIPTION
=========================================================
*/

async function handlePushSubscribe(
  req,
  res
) {
  const customer =
    await getCustomer(req);

  const barber =
    customer
      ? null
      : await getBarber(req);

  if (!customer && !barber) {
    return send(
      res,
      401,
      {
        error:
          "Authentication required"
      }
    );
  }

  const x =
    await body(req);

  const subscription =
    x.subscription;

  if (
    !subscription ||
    !subscription.endpoint
  ) {
    return send(
      res,
      400,
      {
        error:
          "Valid push subscription is required"
      }
    );
  }

  const existing =
    await pool.query(
      `SELECT id
       FROM push_subscriptions
       WHERE endpoint = $1`,
      [
        subscription.endpoint
      ]
    );

  if (!existing.rows.length) {
    await pool.query(
      `INSERT INTO push_subscriptions
       (
         id,
         user_id,
         barber_id,
         endpoint,
         subscription
       )
       VALUES
       (
         $1,
         $2,
         $3,
         $4,
         $5
       )`,
      [
        crypto.randomUUID(),
        customer?.id || null,
        barber?.id || null,
        subscription.endpoint,
        JSON.stringify(
          subscription
        )
      ]
    );
  } else {
    await pool.query(
      `UPDATE push_subscriptions
       SET
         user_id = $1,
         barber_id = $2,
         subscription = $3
       WHERE endpoint = $4`,
      [
        customer?.id || null,
        barber?.id || null,
        JSON.stringify(
          subscription
        ),
        subscription.endpoint
      ]
    );
  }

  return send(
    res,
    200,
    {
      message:
        "Push subscription saved"
    }
  );
}

/*
=========================================================
GET VAPID PUBLIC KEY
=========================================================
*/

async function handlePushPublicKey(
  req,
  res
) {
  return send(
    res,
    200,
    {
      publicKey:
        process.env.VAPID_PUBLIC_KEY ||
        null
    }
  );
}

/*
=========================================================
END OF PART 9
=========================================================
*/
/*
=========================================================
REQUEST ROUTER
PART 10A / 10
=========================================================
*/

async function handleRequest(req, res) {
  try {

    /*
    =======================================================
    CORS PREFLIGHT
    =======================================================
    */

    if (req.method === "OPTIONS") {
      return send(
        res,
        204,
        {}
      );
    }

    /*
    =======================================================
    URL
    =======================================================
    */

    const url =
      new URL(
        req.url,
        `http://${req.headers.host || "localhost"}`
      );

    const pathname =
      url.pathname;

    /*
    =======================================================
    CUSTOMER AUTH ROUTES
    =======================================================
    */

    if (
      req.method === "POST" &&
      pathname === "/api/auth/signup"
    ) {
      return handleCustomerSignup(
        req,
        res
      );
    }

    if (
      req.method === "POST" &&
      pathname === "/api/auth/login"
    ) {
      return handleCustomerLogin(
        req,
        res
      );
    }

    if (
      req.method === "POST" &&
      pathname === "/api/auth/logout"
    ) {
      return handleCustomerLogout(
        req,
        res
      );
    }

    if (
      req.method === "GET" &&
      pathname === "/api/auth/me"
    ) {
      return handleCustomerMe(
        req,
        res
      );
    }

    /*
    =======================================================
    BARBER AUTH ROUTES
    =======================================================
    */

    if (
      req.method === "POST" &&
      pathname === "/api/barber/login"
    ) {
      return handleBarberLogin(
        req,
        res
      );
    }

    if (
      req.method === "POST" &&
      pathname === "/api/barber/logout"
    ) {
      return handleBarberLogout(
        req,
        res
      );
    }

    if (
      req.method === "GET" &&
      pathname === "/api/barber/me"
    ) {
      return handleBarberMe(
        req,
        res
      );
    }

    /*
    =======================================================
    BOOKING ROUTES
    =======================================================
    */

    if (
      req.method === "GET" &&
      pathname === "/api/slots"
    ) {
      return handleAvailableSlots(
        req,
        res,
        url
      );
    }

    if (
      req.method === "POST" &&
      pathname === "/api/bookings"
    ) {
      return handleCreateBooking(
        req,
        res
      );
    }

    if (
      req.method === "GET" &&
      pathname === "/api/bookings"
    ) {
      return handleMyBookings(
        req,
        res
      );
    }

    /*
    =======================================================
    BARBER BOOKING DASHBOARD
    =======================================================
    */

    if (
      req.method === "GET" &&
      pathname === "/api/barber/bookings"
    ) {
      return handleBarberBookings(
        req,
        res
      );
    }

    /*
    =======================================================
    END OF PART 10A
    =======================================================
    */
  /*
=========================================================
BOOKING ACTION ROUTES
PART 10B / 10
=========================================================
*/

    /*
    =======================================================
    BARBER ACCEPT BOOKING
    =======================================================
    */

    if (
      req.method === "PATCH" &&
      pathname.startsWith(
        "/api/barber/bookings/"
      ) &&
      pathname.endsWith(
        "/accept"
      )
    ) {
      const bookingId =
        pathname
          .split("/")
          .filter(Boolean)[3];

      return handleBarberAcceptBooking(
        req,
        res,
        bookingId
      );
    }

    /*
    =======================================================
    BARBER REJECT BOOKING
    =======================================================
    */

    if (
      req.method === "PATCH" &&
      pathname.startsWith(
        "/api/barber/bookings/"
      ) &&
      pathname.endsWith(
        "/reject"
      )
    ) {
      const bookingId =
        pathname
          .split("/")
          .filter(Boolean)[3];

      return handleBarberRejectBooking(
        req,
        res,
        bookingId
      );
    }

    /*
    =======================================================
    BARBER COMPLETE BOOKING
    =======================================================
    */

    if (
      req.method === "PATCH" &&
      pathname.startsWith(
        "/api/barber/bookings/"
      ) &&
      pathname.endsWith(
        "/complete"
      )
    ) {
      const bookingId =
        pathname
          .split("/")
          .filter(Boolean)[3];

      return handleBarberCompleteBooking(
        req,
        res,
        bookingId
      );
    }

    /*
    =======================================================
    BARBER CANCEL BOOKING
    =======================================================
    */

    if (
      req.method === "PATCH" &&
      pathname.startsWith(
        "/api/barber/bookings/"
      ) &&
      pathname.endsWith(
        "/cancel"
      )
    ) {
      const bookingId =
        pathname
          .split("/")
          .filter(Boolean)[3];

      return handleBarberCancelBooking(
        req,
        res,
        bookingId
      );
    }

    /*
    =======================================================
    CUSTOMER CANCEL BOOKING
    =======================================================
    */

    if (
      req.method === "PATCH" &&
      pathname.startsWith(
        "/api/bookings/"
      ) &&
      pathname.endsWith(
        "/cancel"
      )
    ) {
      const bookingId =
        pathname
          .split("/")
          .filter(Boolean)[2];

      return handleCustomerCancelBooking(
        req,
        res,
        bookingId
      );
    }

    /*
    =======================================================
    END OF PART 10B
    =======================================================
    */
  /*
=========================================================
PAYMENT ROUTES
PART 10C / 10
=========================================================
*/

    /*
    =======================================================
    CREATE PAYMENT
    =======================================================
    */

    if (
      req.method === "POST" &&
      pathname === "/api/payments"
    ) {
      return handleCreatePayment(
        req,
        res
      );
    }

    /*
    =======================================================
    VERIFY PAYMENT
    =======================================================
    */

    if (
      req.method === "POST" &&
      pathname === "/api/payments/verify"
    ) {
      return handleVerifyPayment(
        req,
        res
      );
    }

    /*
    =======================================================
    PAYMENT STATUS
    =======================================================
    */

    if (
      req.method === "GET" &&
      pathname === "/api/payments/status"
    ) {
      return handlePaymentStatus(
        req,
        res,
        url
      );
    }

    /*
    =======================================================
    END OF PART 10C
    =======================================================
    */
  /*
=========================================================
NOTIFICATION + PUSH ROUTES
PART 10D / 10
=========================================================
*/

    /*
    =======================================================
    GET NOTIFICATIONS
    =======================================================
    */

    if (
      req.method === "GET" &&
      pathname === "/api/notifications"
    ) {
      return handleGetNotifications(
        req,
        res
      );
    }

    /*
    =======================================================
    MARK ONE NOTIFICATION AS READ
    =======================================================
    */

    if (
      req.method === "PATCH" &&
      pathname.startsWith(
        "/api/notifications/"
      ) &&
      pathname.endsWith(
        "/read"
      )
    ) {
      const notificationId =
        pathname
          .split("/")
          .filter(Boolean)[2];

      return handleMarkNotificationRead(
        req,
        res,
        notificationId
      );
    }

    /*
    =======================================================
    MARK ALL NOTIFICATIONS AS READ
    =======================================================
    */

    if (
      req.method === "PATCH" &&
      pathname ===
        "/api/notifications/read-all"
    ) {
      return handleMarkAllNotificationsRead(
        req,
        res
      );
    }

    /*
    =======================================================
    SAVE PUSH SUBSCRIPTION
    =======================================================
    */

    if (
      req.method === "POST" &&
      pathname === "/api/push/subscribe"
    ) {
      return handlePushSubscribe(
        req,
        res
      );
    }

    /*
    =======================================================
    GET VAPID PUBLIC KEY
    =======================================================
    */

    if (
      req.method === "GET" &&
      pathname === "/api/push/public-key"
    ) {
      return handlePushPublicKey(
        req,
        res
      );
    }

    /*
    =======================================================
    END OF PART 10D
    =======================================================
    */
  /*
=========================================================
STATIC FILE SERVER + ERROR HANDLER + SERVER START
PART 10E / 10
=========================================================
*/

    /*
    =======================================================
    STATIC FILE SERVER
    =======================================================
    */

    let filePath =
      pathname === "/"
        ? path.join(
            PUBLIC_DIR,
            "index.html"
          )
        : path.join(
            PUBLIC_DIR,
            pathname
          );

    /*
    Prevent path traversal
    */

    const resolvedPath =
      path.resolve(filePath);

    const resolvedPublic =
      path.resolve(PUBLIC_DIR);

    if (
      !resolvedPath.startsWith(
        resolvedPublic
      )
    ) {
      return send(
        res,
        403,
        {
          error:
            "Forbidden"
        }
      );
    }

    /*
    -------------------------------------------------------
    Serve requested static file
    -------------------------------------------------------
    */

    try {
      const stat =
        await fs.promises.stat(
          resolvedPath
        );

      if (stat.isFile()) {
        const ext =
          path.extname(
            resolvedPath
          ).toLowerCase();

        const contentTypes = {
          ".html":
            "text/html; charset=utf-8",

          ".css":
            "text/css; charset=utf-8",

          ".js":
            "application/javascript; charset=utf-8",

          ".json":
            "application/json; charset=utf-8",

          ".png":
            "image/png",

          ".jpg":
            "image/jpeg",

          ".jpeg":
            "image/jpeg",

          ".webp":
            "image/webp",

          ".svg":
            "image/svg+xml",

          ".ico":
            "image/x-icon",

          ".txt":
            "text/plain; charset=utf-8"
        };

        const contentType =
          contentTypes[ext] ||
          "application/octet-stream";

        const file =
          await fs.promises.readFile(
            resolvedPath
          );

        return send(
          res,
          200,
          file,
          contentType
        );
      }
    } catch {}

    /*
    -------------------------------------------------------
    SPA FALLBACK
    -------------------------------------------------------

    If a normal page does not exist,
    serve index.html so frontend
    routes can still work.
    */

    if (
      req.method === "GET" &&
      !pathname.startsWith("/api/")
    ) {
      try {
        const indexFile =
          await fs.promises.readFile(
            path.join(
              PUBLIC_DIR,
              "customer.html"
            )
          );

        return send(
          res,
          200,
          indexFile,
          "text/html; charset=utf-8"
        );
      } catch {}
    }

    /*
    =======================================================
    404
    =======================================================
    */

    return send(
      res,
      404,
      {
        error:
          "Route or file not found"
      }
    );

  } catch (err) {

    console.error(
      "Request error:",
      err
    );

    if (!res.headersSent) {
      return send(
        res,
        500,
        {
          error:
            "Internal server error"
        }
      );
    }

    res.end();
  }
}

/*
=========================================================
SERVER START
=========================================================
*/
const server =
  http.createServer(
    handleRequest
  );
async function startServer() {
  try {

    await initDB();

    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `StyleSpot server running on port ${PORT}`
        );
      }
    );

  } catch (err) {

    console.error(
      "Failed to start server:",
      err
    );

    process.exit(1);
  }
}

startServer();

/*
=========================================================
END OF SERVER.JS
=========================================================
*/
