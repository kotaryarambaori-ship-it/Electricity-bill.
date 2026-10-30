const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(express.json({ limit: "100kb" }));

const DB = process.env.DATABASE_URL;
const SECRET = process.env.JWT_SECRET || "change-this-secret";
const pool = new Pool({
  connectionString: DB,
  ssl: DB && !/localhost|127\.0\.0\.1/.test(DB) ? { rejectUnauthorized: false } : false,
});

// Apni tables alag schema "pb" me rakhte hain, taaki dusre project se takrav na ho
pool.on("connect", (client) => {
  client.query("set search_path to pb");
});

async function init() {
  await pool.query("create schema if not exists pb");
  await pool.query(`
    create table if not exists users(
      id serial primary key,
      email text unique not null,
      pass text not null,
      created_at timestamptz default now());
    create table if not exists bills(
      id serial primary key,
      user_id int not null references users(id) on delete cascade,
      name text, consumer_no text, month text,
      units numeric(12,2) not null,
      energy numeric(12,2) not null,
      current_amt numeric(12,2) not null,
      payable numeric(12,2) not null,
      remaining numeric(12,2) not null,
      created_at timestamptz default now());
    create index if not exists bills_user_idx on bills(user_id);
  `);
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  try {
    req.uid = jwt.verify(h.replace("Bearer ", ""), SECRET).id;
    next();
  } catch (e) {
    res.status(401).json({ error: "Login karo" });
  }
}

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : NaN);

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("select 1");
    res.json({ ok: true, db: "connected" });
  } catch (e) {
    console.error("health error:", e.message);
    res.status(500).json({ ok: false, db: "error" });
  }
});

async function creds(req, res) {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email)) { res.status(400).json({ error: "Sahi email daalo" }); return null; }
  if (password.length < 6) { res.status(400).json({ error: "Password kam se kam 6 akshar ka ho" }); return null; }
  return { email, password };
}

app.post("/api/auth/register", async (req, res) => {
  const c = await creds(req, res);
  if (!c) return;
  try {
    const hash = await bcrypt.hash(c.password, 10);
    const r = await pool.query("insert into users(email,pass) values($1,$2) returning id", [c.email, hash]);
    res.status(201).json({ token: jwt.sign({ id: r.rows[0].id }, SECRET, { expiresIn: "7d" }) });
  } catch (e) {
    console.error("register error:", e.message);
    if (e.code === "23505") return res.status(409).json({ error: "Ye email pehle se hai. Login karo" });
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const c = await creds(req, res);
  if (!c) return;
  try {
    const r = await pool.query("select id,pass from users where email=$1", [c.email]);
    if (!r.rows.length || !(await bcrypt.compare(c.password, r.rows[0].pass)))
      return res.status(401).json({ error: "Email ya password galat hai" });
    res.json({ token: jwt.sign({ id: r.rows[0].id }, SECRET, { expiresIn: "7d" }) });
  } catch (e) {
    console.error("login error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/bills", auth, async (req, res) => {
  try {
    const r = await pool.query("select * from bills where user_id=$1 order by created_at desc limit 200", [req.uid]);
    res.json(r.rows);
  } catch (e) {
    console.error("bills list error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/bills", auth, async (req, res) => {
  const b = req.body;
  const v = [b.units, b.energy, b.current, b.payable, b.remaining].map(num);
  if (v.some((x) => Number.isNaN(x))) return res.status(400).json({ error: "Bill ke numbers galat hain" });
  try {
    const r = await pool.query(
      "insert into bills(user_id,name,consumer_no,month,units,energy,current_amt,payable,remaining) values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning id",
      [req.uid, String(b.name || "").slice(0, 100), String(b.no || "").slice(0, 50), String(b.month || "").slice(0, 10), ...v]
    );
    res.status(201).json({ id: r.rows[0].id });
  } catch (e) {
    console.error("bill save error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/api/bills/:id", auth, async (req, res) => {
  try {
    await pool.query("delete from bills where id=$1 and user_id=$2", [parseInt(req.params.id, 10) || 0, req.uid]);
    res.json({ ok: true });
  } catch (e) {
    console.error("bill delete error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/api/bills", auth, async (req, res) => {
  try {
    await pool.query("delete from bills where user_id=$1", [req.uid]);
    res.json({ ok: true });
  } catch (e) {
    console.error("bills clear error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT || 5000;
init()
  .then(() => app.listen(PORT, () => console.log("Server running on " + PORT)))
  .catch((e) => { console.error("DB setup failed:", e.message); process.exit(1); });
