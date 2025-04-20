require("dotenv").config();
const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const CLUB_SECRET = process.env.CLUB_SECRET;
const app = express();

// PostgreSQL DB connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

console.log("Connecting to DB:", process.env.DB_NAME);

pool.connect()
  .then(() => console.log("Connected to PostgreSQL!"))
  .catch((err) => console.error("PostgreSQL connection error", err));

// Middleware setup
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

// Make user available to all templates
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

// Passport Strategy
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
      const user = result.rows[0];
      if (!user) return done(null, false, { message: "Incorrect username." });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return done(null, false, { message: "Incorrect password." });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/log-in");
}

// ROUTES
app.get("/", async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT messages.id, messages.title, messages.message, messages.timestamp,
             users.first_name, users.last_name, users.is_member
      FROM messages
      JOIN users ON messages.user_id = users.id
      ORDER BY messages.timestamp DESC
    `);
    const messages = result.rows;
    res.render("index", { messages });
  } catch (err) {
    next(err);
  }
});

app.get("/new-message", ensureAuthenticated, (req, res) => {
  res.render("new-message");
});

app.post("/new-message", ensureAuthenticated, async (req, res, next) => {
  const { title, message } = req.body;
  if (!title || !message) return res.send("Both fields are required.");
  try {
    await pool.query(
      "INSERT INTO messages (title, message, user_id) VALUES ($1, $2, $3)",
      [title, message, req.user.id]
    );
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

// DELETE MESSAGE (Admins Only)
app.post("/delete-message/:id", ensureAuthenticated, async (req, res, next) => {
  if (!req.user.is_admin) return res.status(403).send("❌ Access denied. Admins only.");
  try {
    await pool.query("DELETE FROM messages WHERE id = $1", [req.params.id]);
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

// Sign-up
app.get("/sign-up", (req, res) => res.render("sign-up"));
app.post("/sign-up", async (req, res, next) => {
  const { firstName, lastName, username, password, confirmPassword } = req.body;
  if (!firstName || !lastName || !username || !password || !confirmPassword)
    return res.send("All fields are required.");
  if (password !== confirmPassword)
    return res.send("Passwords do not match.");
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (first_name, last_name, username, password) VALUES ($1, $2, $3, $4)",
      [firstName, lastName, username, hashedPassword]
    );
    res.redirect("/log-in");
  } catch (err) {
    console.error(err);
    res.send("There was an error creating your account.");
  }
});

// Login & Logout
app.get("/log-in", (req, res) => res.render("log-in"));
app.post("/log-in", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/log-in",
}));
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

// Join the Club
app.get("/join-club", ensureAuthenticated, (req, res) => {
  res.render("join-club");
});
app.post("/join-club", ensureAuthenticated, async (req, res, next) => {
  const { secret } = req.body;
  if (secret === CLUB_SECRET) {
    try {
      await pool.query("UPDATE users SET is_member = true WHERE id = $1", [req.user.id]);
      res.send("🎉 Welcome to the Club! You’re now a member.");
    } catch (err) {
      next(err);
    }
  } else {
    res.send("❌ Incorrect passcode.");
  }
});

// Start server


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
