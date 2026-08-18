const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const PUBLIC = __dirname;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const SLOTS = [
  "09:00 AM","09:30 AM","10:00 AM","10:30 AM",
  "11:00 AM","11:30 AM","12:00 PM","12:30 PM",
  "01:00 PM","01:30 PM","02:00 PM","02:30 PM",
  "03:00 PM","03:30 PM","04:00 PM","04:30 PM",
  "05:00 PM","05:30 PM","06:00 PM","06:30 PM",
  "07:00 PM","07:30 PM","08:00 PM","08:30 PM"
];

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS bookings (
      id UUID PRIMARY KEY,
      booking_no TEXT UNIQUE NOT NULL,
      user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      service TEXT NOT NULL,
      date DATE NOT NULL,
      time TEXT NOT NULL,
      notes TEXT DEFAULT '',
      status TEXT DEFAULT 'Booked',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log("Database ready");
}

function send(res, code, data, type = "application/json") {
  res.writeHead(code, {
    "Content-Type": type,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS"
  });

  res.end(type.includes("json") ? JSON.stringify(data) : data);
}

function body(req) {
  return new Promise((resolve, reject) => {
    let b = "";

    req.on("data", chunk => b += chunk);

    req.on("end", () => {
      try {
        resolve(JSON.parse(b || "{}"));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
  });
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");

    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`${salt}:${derivedKey.toString("hex")}`);
    });
  });
}

function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const [salt, key] = stored.split(":");

    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);

      const storedKey = Buffer.from(key, "hex");
      const isValid =
        storedKey.length === derivedKey.length &&
        crypto.timingSafeEqual(storedKey, derivedKey);

      resolve(isValid);
    });
  });
}

function getToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) return null;

  return header.slice(7);
}

async function getUser(req) {
  const token = getToken(req);

  if (!token) return null;

  const result = await pool.query(
    `SELECT users.id, users.name, users.phone
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.token = $1`,
    [token]
  );

  return result.rows[0] || null;
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "OPTIONS") {
      return send(res, 204, "");
    }

    const u = new URL(req.url, `http://${req.headers.host}`);

    // SIGN UP
    if (req.method === "POST" && u.pathname === "/api/signup") {
      const x = await body(req);

      if (!x.name || !x.phone || !x.password) {
        return send(res, 400, {
          error: "Name, phone and password are required"
        });
      }

      if (x.password.length < 6) {
        return send(res, 400, {
          error: "Password must be at least 6 characters"
        });
      }

      const existing = await pool.query(
        "SELECT id FROM users WHERE phone = $1",
        [x.phone]
      );

      if (existing.rows.length) {
        return send(res, 409, {
          error: "An account with this phone number already exists"
        });
      }

      const id = crypto.randomUUID();
      const passwordHash = await hashPassword(x.password);

      await pool.query(
        `INSERT INTO users (id, name, phone, password_hash)
         VALUES ($1, $2, $3, $4)`,
        [id, x.name, x.phone, passwordHash]
      );

      return send(res, 201, {
        message: "Account created successfully"
      });
    }

    // LOGIN
    if (req.method === "POST" && u.pathname === "/api/login") {
      const x = await body(req);

      if (!x.phone || !x.password) {
        return send(res, 400, {
          error: "Phone and password are required"
        });
      }

      const result = await pool.query(
        "SELECT * FROM users WHERE phone = $1",
        [x.phone]
      );

      if (!result.rows.length) {
        return send(res, 401, {
          error: "Invalid phone number or password"
        });
      }

      const user = result.rows[0];
      const valid = await verifyPassword(
        x.password,
        user.password_hash
      );

      if (!valid) {
        return send(res, 401, {
          error: "Invalid phone number or password"
        });
      }

      const token = crypto.randomBytes(32).toString("hex");

      await pool.query(
        `INSERT INTO sessions (token, user_id)
         VALUES ($1, $2)`,
        [token, user.id]
      );

      return send(res, 200, {
        message: "Login successful",
        token,
        user: {
          id: user.id,
          name: user.name,
          phone: user.phone
        }
      });
    }

    // CURRENT USER
    if (req.method === "GET" && u.pathname === "/api/me") {
      const user = await getUser(req);

      if (!user) {
        return send(res, 401, { error: "Not logged in" });
      }

      return send(res, 200, { user });
    }

    // LOGOUT
    if (req.method === "POST" && u.pathname === "/api/logout") {
      const token = getToken(req);

      if (token) {
        await pool.query(
          "DELETE FROM sessions WHERE token = $1",
          [token]
        );
      }

      return send(res, 200, {
        message: "Logged out"
      });
    }

    // AVAILABLE SLOTS
    if (req.method === "GET" && u.pathname === "/api/slots") {
      const date = u.searchParams.get("date");

      const result = await pool.query(
        `SELECT time
         FROM bookings
         WHERE date = $1
         AND status != 'Cancelled'`,
        [date]
      );

      return send(res, 200, {
        slots: SLOTS,
        booked: result.rows.map(x => x.time)
      });
    }

    // CREATE BOOKING
    if (req.method === "POST" && u.pathname === "/api/book") {
      const x = await body(req);
      const user = await getUser(req);

      if (!x.name || !x.phone || !x.service || !x.date || !x.time) {
        return send(res, 400, {
          error: "Fill all required fields"
        });
      }

      const existing = await pool.query(
        `SELECT id
         FROM bookings
         WHERE date = $1
         AND time = $2
         AND status != 'Cancelled'`,
        [x.date, x.time]
      );

      if (existing.rows.length) {
        return send(res, 409, {
          error: "Slot already booked"
        });
      }

      const id = crypto.randomUUID();
      const bookingNo =
        "SS-" + Math.floor(100000 + Math.random() * 900000);

      const result = await pool.query(
        `INSERT INTO bookings
         (id, booking_no, user_id, name, phone, service, date, time, notes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING *`,
        [
          id,
          bookingNo,
          user ? user.id : null,
          x.name,
          x.phone,
          x.service,
          x.date,
          x.time,
          x.notes || ""
        ]
      );

      return send(res, 201, result.rows[0]);
    }

    // ALL BOOKINGS - BARBER
    if (req.method === "GET" && u.pathname === "/api/bookings") {
      const result = await pool.query(
        "SELECT * FROM bookings ORDER BY date, time"
      );

      return send(res, 200, result.rows);
    }

    // MY BOOKINGS
    if (req.method === "GET" && u.pathname === "/api/my-bookings") {
      const user = await getUser(req);

      if (!user) {
        return send(res, 401, {
          error: "Please login first"
        });
      }

      const result = await pool.query(
        `SELECT *
         FROM bookings
         WHERE user_id = $1
         ORDER BY date DESC, time DESC`,
        [user.id]
      );

      return send(res, 200, result.rows);
    }

    // UPDATE BOOKING
    if (
      req.method === "PATCH" &&
      u.pathname.startsWith("/api/bookings/")
    ) {
      const id = u.pathname.split("/").pop();
      const x = await body(req);

      const result = await pool.query(
        `UPDATE bookings
         SET status = COALESCE($1, status)
         WHERE id = $2
         RETURNING *`,
        [x.status || null, id]
      );

      if (!result.rows.length) {
        return send(res, 404, {
          error: "Not found"
        });
      }

      return send(res, 200, result.rows[0]);
    }

    // STATIC FILES
    let file =
      u.pathname === "/"
        ? "customer.html"
        : u.pathname.slice(1);

    const full = path.join(PUBLIC, file);

    fs.readFile(full, (err, data) => {
      if (err) {
        return send(res, 404, "Not found", "text/plain");
      }

      const ext = path.extname(full);

      const types = {
        ".html": "text/html",
        ".css": "text/css",
        ".js": "text/javascript"
      };

      send(
        res,
        200,
        data,
        types[ext] || "application/octet-stream"
      );
    });

  } catch (err) {
    console.error(err);

    send(res, 500, {
      error: "Server error"
    });
  }
});

initDB()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`StyleSpot running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
