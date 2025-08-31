import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from 'dotenv';
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import flash from "connect-flash";
import { spawn } from "child_process";

dotenv.config();

const app = express();
const port = 8000;
const saltRounds = 10;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: "TOPSECRET",
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(flash());
app.use((req, res, next) => {
  res.locals.error = req.flash("error");
  res.locals.success = req.flash("success");
  res.locals.user = req.user || null;
  next();
});

const CATEGORY_MAP = {
    'Arts and Entertainment': '4d4b7104d754a06370d81259',
    'Amusement Park': '4bf58dd8d48988d182941735',
    'Aquarium': '4fceea171983d5d06c3e9823',
    'Arcade': '4bf58dd8d48988d1e1931735',
    'Art Gallery': '4bf58dd8d48988d1e2931735',
    'Bowling Alley': '4bf58dd8d48988d1e4931735',
    'Casino': '4bf58dd8d48988d17c941735',
    'Comedy Club': '4bf58dd8d48988d18e941735',
    'Exhibit': '56aa371be4b08b9a8d573532',
    'Fair': '4eb1daf44b900d56c88a4600',
    'Gaming Cafe': '4bf58dd8d48988d18d941735',
    'General Entertainment': '4bf58dd8d48988d1f1931735',
    'Karaoke Box': '5744ccdfe4b0c0459246b4bb',
    'Laser Tag Center': '52e81612bcbc57f1066b79e6',
    'Mini Golf Course': '52e81612bcbc57f1066b79eb',
    'Movie Theater': '4bf58dd8d48988d17f941735',
    'Museum': '4bf58dd8d48988d181941735',
    'Night Club': '4bf58dd8d48988d11f941735',
    'Performing Arts Venue': '4bf58dd8d48988d1f2931735',
    'Stadium': '4bf58dd8d48988d184941735',
    'Zoo': '4bf58dd8d48988d17b941735',
    'Water Park': '4bf58dd8d48988d193941735',
    'Restaurant': '4d4b7105d754a06374d81259',
    'Cafe': '63be6904847c3692a84b9bb6',
    'Bar': '4bf58dd8d48988d116941735',
    'Hotel': '4bf58dd8d48988d1fa931735',
    'Resort': '4bf58dd8d48988d12f951735',
    'Vacation Rental': '56aa371be4b08b9a8d5734e1',
    'Park': '4bf58dd8d48988d163941735',
    'National Park': '52e81612bcbc57f1066b7a21',
    'Beach': '4bf58dd8d48988d1e2941735',
    'Historic Site': '4deefb944765f83613cdba6e',
    'Theater': '4bf58dd8d48988d137941735',
    'Event': '4d4b7105d754a06373d81259'
}

app.use(passport.initialize());
app.use(passport.session());

// ✅ Database connection
const db = new pg.Client({
  host: process.env.HOST,
  port: process.env.DB_PORT || 5432,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
});

(async () => {
  try {
    await db.connect();
    console.log("Connected to Postgres");
  } catch (err) {
    console.error("Database connection failed:", err);
    process.exit(1);
  }
})();

// --- Routes (signup/login trimmed for brevity) ---
app.get("/", (req, res) => {
    res.render("index.ejs");
});

app.get("/sign-up", (req, res) => {
    // Pass query params to the sign-up page
    const { group_id, email } = req.query;
    res.render("sign-up.ejs", { 
        inviteGroupId: group_id || null,
        inviteEmail: email || null 
    });
});

app.get("/log-in", (req, res) => {
    // Pass query params to the login page
    const { group_id, email } = req.query;
    res.render("log-in.ejs", {
        inviteGroupId: group_id || null,
        inviteEmail: email || null
    });
});

app.post("/sign-up", async (req, res) => {
    const { username, email, password, group_id, invite_email } = req.body;

    console.log("Sign-up attempt:", { email, username, group_id, invite_email });

    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

        if (checkResult.rows.length > 0) {
            return res.render("sign-up.ejs", { 
                err: "Email already exists, try logging in.",
                inviteGroupId: group_id,
                inviteEmail: invite_email
            });
        }

        if (password.length < 8) {
            return res.render("sign-up.ejs", { 
                passwordErr: "Password should be greater than 8 characters",
                inviteGroupId: group_id,
                inviteEmail: invite_email
            });
        }

        const hash = await bcrypt.hash(password, saltRounds);

        const result = await db.query(
            "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING *",
            [username, email, hash]
        );

        const newUser = result.rows[0];
        console.log("New user created:", { userId: newUser.user_id, email: newUser.email });

        req.login(newUser, async (err) => {
            if (err) {
                console.error("Login after signup failed:", err);
                return res.redirect("/log-in");
            }

            console.log("User logged in successfully");

            // Check if there's a pending group invitation
            if (group_id && invite_email) {
                console.log(`Processing group invitation: groupId=${group_id}, invitedEmail=${invite_email}, userEmail=${email}`);

                // Get group details first
                const groupResult = await db.query(
                    "SELECT group_name FROM groups WHERE group_id = $1",
                    [group_id]
                );

                if (groupResult.rows.length === 0) {
                    console.log("Group not found:", group_id);
                    req.flash("error", "The group you were invited to no longer exists.");
                    return res.redirect("/groups_list");
                }

                const groupName = groupResult.rows[0].group_name;

                // Verify this signup is for the invited email
                if (invite_email.trim().toLowerCase() === email.trim().toLowerCase()) {
                    console.log("Email matches, adding user to group");
                    
                    try {
                        // Check if already a member
                        const existingMember = await db.query(
                            "SELECT * FROM group_members WHERE group_id = $1 AND user_id = $2",
                            [group_id, newUser.user_id]
                        );

                        if (existingMember.rows.length === 0) {
                            // Add user to group
                            const memberInsert = await db.query(
                                "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, $3) RETURNING *",
                                [group_id, newUser.user_id, "member"]
                            );
                            
                            if (memberInsert.rows.length > 0) {
                                console.log("Successfully added user to group:", memberInsert.rows[0]);
                                req.flash("success", "Account created and joined group successfully!");
                                return res.redirect(`/group/${encodeURIComponent(groupName)}`);
                            }
                        } else {
                            req.flash("info", "You're already a member of this group.");
                            return res.redirect(`/group/${encodeURIComponent(groupName)}`);
                        }
                    } catch (err) {
                        console.error("Database error while adding group member:", err);
                        req.flash("error", "An error occurred while joining the group.");
                    }
                } else {
                    console.log("Email mismatch:", invite_email, "vs", email);
                    req.flash("error", "This invitation was not for your email address.");
                }
            }

            return res.redirect("/home");
        });
    } catch (err) {
        console.error("Sign-up error:", err);
        return res.status(500).send("Internal Server Error");
    }
});

// Log-in
app.post("/log-in", passport.authenticate("local", {
    failureRedirect: "/log-in",
    failureFlash: true
}), async (req, res) => {
    const { group_id, invite_email } = req.body; // Get from form data

    if (group_id && invite_email) {
        console.log(`Processing invite: groupId=${group_id}, invitedEmail=${invite_email}, userEmail=${req.user.email}`);

        // Verify group exists
        const groupResult = await db.query(
            "SELECT group_name FROM groups WHERE group_id = $1",
            [group_id]
        );

        if (groupResult.rows.length === 0) {
            req.flash("error", "That group no longer exists.");
            return res.redirect("/groups_list");
        }

        const groupName = groupResult.rows[0].group_name;

        // Check email matches
        if (invite_email.trim().toLowerCase() === req.user.email.trim().toLowerCase()) {
            try {
                const existing = await db.query(
                    "SELECT * FROM group_members WHERE group_id=$1 AND user_id=$2",
                    [group_id, req.user.user_id]
                );

                if (existing.rows.length === 0) {
                    await db.query(
                        "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, $3)",
                        [group_id, req.user.user_id, "member"]
                    );
                    req.flash("success", "You joined the group!");
                } else {
                    req.flash("info", "You're already in this group.");
                }

                return res.redirect(`/group/${encodeURIComponent(groupName)}`);
            } catch (err) {
                console.error("Join failed:", err);
                req.flash("error", "Could not join group, please try again.");
                return res.redirect("/groups_list");
            }
        } else {
            req.flash("error", "This invite is not for your email address.");
            return res.redirect("/groups_list");
        }
    }

    // If no invite → just go home
    res.redirect("/plan");
});


app.get("/home", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("home.ejs", { itinerary: req.session.itinerary || null });
  } else {
    res.redirect("/sign-up");
  }
});

app.get("/plan", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("plan.ejs", {map: CATEGORY_MAP});
  } else {
    res.redirect("/sign-up");
  }
});

app.get("/logout", (req, res, next) => {
    req.logout(function (err) {
        if (err) { return next(err); }
        req.flash("success", "You have logged out successfully.");
        res.redirect("/log-in");
    });
});

// ✅ Generate-plan route using Python researcher_agent
// 

// ✅ Generate-plan route using Python researcher_agent
app.post("/generate-plan", async (req, res) => {
  try {
    const place = req.body.place;
    const radius = parseInt(req.body.radius) || 5; // km
    const customInterest = req.body["custom-interest"];
    const selectedInterests = JSON.parse(req.body["selected-interests"] || "[]");

    const inputPayload = {
      city: place || "Chennai",
      radius_m: radius * 1000,
      min_price: req.body.min_price ? parseInt(req.body.min_price) : null,
      max_price: req.body.max_price ? parseInt(req.body.max_price) : null,
      categories: selectedInterests.concat(customInterest ? [customInterest] : []),
    };

    // ✅ Spawn researcher_agent.py
    const py = spawn("python", ["researcher_agent.py"], {
      cwd: __dirname,
    });

    py.stdin.write(JSON.stringify(inputPayload));
    py.stdin.end();

    let dataBuffer = "";
    py.stdout.on("data", (data) => {
      dataBuffer += data.toString();
    });

    py.stderr.on("data", (data) => {
      console.error("Python error:", data.toString());
    });

    py.on("close", (code) => {
      try {
        const _result = JSON.parse(dataBuffer);
        // ✅ Render result.ejs with Python agent output
        res.render("result.ejs", { result: _result });
      } catch (err) {
        console.error("Failed to parse Python output", err, dataBuffer);
        res.status(500).send("Error parsing results from Python agent");
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: "Failed to generate plan" });
  }
});


passport.use(new Strategy({
    usernameField: "email",
    passwordField: "password"
}, async function verify(email, password, cb) {
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

        if (result.rows.length === 0) {
            return cb(null, false, { message: "User not found, please sign up." });
        }

        const user = result.rows[0];
        const matched = await bcrypt.compare(password, user.password_hash);
        
        if (matched) {
            return cb(null, user);
        } else {
            return cb(null, false, { message: "Incorrect Password. Please enter the right password." });
        }
    } catch (err) {
        return cb(err);
    }
}));

passport.serializeUser((user, cb) => {
    cb(null, user.user_id);
});

passport.deserializeUser(async (userId, cb) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE user_id = $1", [userId]);
        if (result.rows.length > 0) {
            cb(null, result.rows[0]);
        } else {
            cb(null, false);
        }
    } catch (err) {
        cb(err);
    }
});

app.listen(port, () => {
    console.log(`Server running at port ${port}`);
});