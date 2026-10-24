const express = require("express");
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;

const app = express();

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  CALLBACK_URL,
  SESSION_SECRET,
  FRONTEND_URL
} = process.env;

if (
  !DISCORD_CLIENT_ID ||
  !DISCORD_CLIENT_SECRET ||
  !CALLBACK_URL ||
  !SESSION_SECRET ||
  !FRONTEND_URL
) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(session({
  name: "nova.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(new DiscordStrategy({
  clientID: DISCORD_CLIENT_ID,
  clientSecret: DISCORD_CLIENT_SECRET,
  callbackURL: CALLBACK_URL,
  scope: ["identify"]
}, (accessToken, refreshToken, profile, done) => {
  done(null, {
    id: profile.id,
    username: profile.username,
    global_name: profile.global_name || profile.username,
    avatar: profile.avatar
  });
}));

app.get("/", (req, res) => {
  res.send("Nova Builder Discord Login API is running!");
});

app.get("/auth/discord", passport.authenticate("discord"));

app.get("/auth/discord/callback",
  passport.authenticate("discord", {
    failureRedirect: `${FRONTEND_URL}/?login=failed`
  }),
  (req, res) => {
    res.redirect(FRONTEND_URL);
  }
);

app.get("/auth/me", (req, res) => {
  res.set("Cache-Control", "no-store");

  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not logged in" });
  }

  res.json(req.user);
});

app.post("/auth/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);

    req.session.destroy(err => {
      if (err) return next(err);

      res.clearCookie("nova.sid", {
        httpOnly: true,
        secure: true,
        sameSite: "lax"
      });

      res.status(200).json({ success: true });
    });
  });
});

app.use((err, req, res, next) => {
  console.error("Request failed:", err.message);
  res.status(500).json({ error: "An internal server error occurred." });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Nova Builder backend running on port ${PORT}`);
});
