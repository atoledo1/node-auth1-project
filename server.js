const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const bcryptjs = require("bcryptjs");
const KnexSessionStore = require("connect-session-knex")(session);

const usersRouter = require("./users/usersRouter.js");
const authenticate = require("./auth/auth.js");
const dbConnection = require("./data/connection");
const Users = require("./users/usersModel.js");

const server = express();

const sessionConfiguration = {
  name: "book",
  secret: process.env.SESSION_SECRET || "So many books, so little time",
  cookie: {
    maxAge: 1000 * 60 * 5,
    secure: process.env.USE_SECURE_COOKIES || false,
    httpOnly: true,
  },
  resave: false,
  saveUninitiailized: true,
  store: new KnexSessionStore({
    knex: dbConnection,
    tablename: "sessions",
    sidfieldname: "sid",
    createtable: true,
    clearInterval: 1000 * 60 * 30,
  }),
};

server.use(session(sessionConfiguration));
server.use(helmet());
server.use(express.json());

server.use("/api/users", authenticate, usersRouter);

server.post("/api/register", (req, res) => {
  let credentials = req.body;
  const hash = hashString(credentials.password);
  credentials.password = hash;
  Users.add(credentials)
    .then((saved) => {
      res.status(201).json({ data: saved });
    })
    .catch((err) => {
      if (err.message.includes("Failed")) {
        res.status(500).json({ message: "That username is already taken." });
      } else {
        res.status(500).json({ error: err.message });
      }
    });
});

server.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  Users.findBy({ username })
    .then((users) => {
      const user = users[0];
      if (user && bcryptjs.compareSync(password, user.password)) {
        req.session.loggedIn = true;
        req.session.username = user.username;
        res.status(200).json({ message: "Welcome!" });
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch((err) => {
      res.status(500).json({ error: err.message });
    });
});

function hashString(str) {
  const rounds = process.env.HASH_ROUNDS || 4;
  return bcryptjs.hashSync(str, rounds);
}

module.exports = server;
