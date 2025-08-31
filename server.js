import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from 'dotenv';
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
import flash from "connect-flash";
import sgMail from "@sendgrid/mail";
import fetch from "node-fetch";
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

app.use(session({
    secret: "TOPSECRET",
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false, // Set to true if using HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use(flash());

app.use((req, res, next) => {
    res.locals.error = req.flash("error");
    res.locals.success = req.flash("success");
    res.locals.user = req.user || null;
    next();
});

app.use(passport.initialize());
app.use(passport.session());

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

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Helper function to get group details with members
// async function getGroupDetails(groupId) {
//     try {
//         const groupResult = await db.query(
//             `SELECT g.group_id, g.group_name, g.created_by, u.email AS created_by_email, u.username AS created_by_username
//              FROM groups g
//              JOIN users u ON g.created_by = u.user_id
//              WHERE g.group_id = $1`,
//             [groupId]
//         );

//         if (groupResult.rows.length === 0) {
//             return null;
//         }

//         const group = groupResult.rows[0];

//         const membersResult = await db.query(
//             `SELECT u.user_id, u.username, u.email, gm.role
//              FROM users u
//              JOIN group_members gm ON u.user_id = gm.user_id
//              WHERE gm.group_id = $1
//              ORDER BY u.username`,
//             [groupId]
//         );

//         const members = membersResult.rows.map(member => ({
//             ...member,
//             isAdmin: member.user_id === group.created_by
//         }));

//         return {
//             ...group,
//             members
//         };
//     } catch (err) {
//         console.error("Error getting group details:", err);
//         return null;
//     }
// }



// Routes
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

// Sign-up
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
    res.redirect("/home");
});

// Join route (clicked from invite link)
// app.get('/join', async (req, res) => {
//     const { group_id, email } = req.query;

//     if (!group_id || !email) {
//         return res.status(400).send("Invalid invite link");
//     }

//     // Check if user is authenticated
//     if (!req.isAuthenticated()) {
//         // Not logged in → redirect to sign-up/login with query params
//         return res.redirect(`/sign-up?group_id=${group_id}&email=${encodeURIComponent(email)}`);
//     }

//     // If logged in, check if it's the right user
//     if (req.user.email.toLowerCase() === email.toLowerCase()) {
//         try {
//             // Get group info
//             const groupResult = await db.query(
//                 "SELECT group_name FROM groups WHERE group_id = $1",
//                 [group_id]
//             );

//             if (groupResult.rows.length === 0) {
//                 req.flash("error", "This group no longer exists.");
//                 return res.redirect("/groups_list");
//             }

//             const groupName = groupResult.rows[0].group_name;

//             // Check if already a member
//             const existingMember = await db.query(
//                 "SELECT * FROM group_members WHERE group_id = $1 AND user_id = $2",
//                 [group_id, req.user.user_id]
//             );

//             if (existingMember.rows.length === 0) {
//                 // Add to group
//                 await db.query(
//                     "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, $3)",
//                     [group_id, req.user.user_id, "member"]
//                 );
//                 req.flash("success", "You've joined the group!");
//             } else {
//                 req.flash("info", "You're already a member of this group.");
//             }

//             return res.redirect(`/group/${encodeURIComponent(groupName)}`);
//         } catch (err) {
//             console.error("Error adding user to group:", err);
//             req.flash("error", "Failed to join group. Please try again.");
//             return res.redirect("/groups_list");
//         }
//     } else {
//         req.flash("error", "This invite is not for your account. Please log in with the invited email address.");
//         return res.redirect("/groups_list");
//     }
// });

// Inner pages
app.get("/home", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("home.ejs");
    } else {
        res.redirect("/sign-up");
    }
});

app.get("/plan", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("plan.ejs");
    } else {
        res.redirect("/sign-up");
    }
});

// app.get("/group", (req, res) => {
//     if (req.isAuthenticated()) {
//         res.render("group.ejs");
//     } else {
//         res.redirect("/sign-up");
//     }
// });

// app.get("/offline", (req, res) => {
//     if (req.isAuthenticated()) {
//         res.render("offline.ejs");
//     } else {
//         res.redirect("/sign-up");
//     }
// });

app.get("/logout", (req, res, next) => {
    req.logout(function (err) {
        if (err) { return next(err); }
        req.flash("success", "You have logged out successfully.");
        res.redirect("/log-in");
    });
});

// app.post("/generate-plan", (req, res) => {
//     const place = req.body.place;
//     const checkin = req.body.checkin;
//     const checkout = req.body.checkout;
//     const radius = req.body.radius;
//     const customInterest = req.body["custom-interest"];
//     const selectedInterests = JSON.parse(req.body["selected-interests"] || "[]");
//     console.log(place, checkin, checkout, radius, customInterest, selectedInterests);
//     res.redirect("/home");
// });



app.post("/generate-plan", async (req, res) => {
  try {
    const place = req.body.place;
    const minprice = req.body.min_price;
    const maxprice = req.body.max_price;
    const radius = parseInt(req.body.radius) || 5;
    const customInterest = req.body["custom-interest"];
    const selectedInterests = JSON.parse(req.body["selected-interests"] || "[]");

    // Prepare payload for Python agents
    const inputPayload = {
      city: place,
      lat: req.body.lat || 13.0827, // fallback if you don’t have coordinates
      lon: req.body.lon || 80.2707,
      radius: radius, // convert meters → km (your researcher expects km)
      min_price: minprice,
      max_price: maxprice,
      interests: selectedInterests.concat(customInterest ? [customInterest] : [])
    };

    // Spawn Python researcher agent (which calls planner_agent internally)
    const py = spawn("python", ["researcher_agent.py"]);

    let dataBuffer = "";
    py.stdout.on("data", (data) => {
      dataBuffer += data.toString();
    });

    py.stderr.on("data", (data) => {
      console.error(`Python error: ${data}`);
    });

    py.on("close", () => {
      try {
        // researcher_agent prints debug logs + final JSON
        // Find the last valid JSON block
        const lastBrace = dataBuffer.lastIndexOf("}");
        const jsonStr = dataBuffer.slice(0, lastBrace + 1);
        const output = JSON.parse(jsonStr);

        res.json(output);
      } catch (err) {
        console.error("Failed to parse Python output", err);
        res.status(500).json({ error: "Invalid output from Python" });
      }
    });

    // Send JSON input to Python via stdin
    py.stdin.write(JSON.stringify(inputPayload));
    py.stdin.end();

  } catch (err) {
    console.error(err);
    res.status(500).send({ error: "Failed to generate plan" });
  }
});


// app.get("/groups_list", async (req, res) => {
//     if (req.isAuthenticated()) {
//         try {
//             const result = await db.query("SELECT user_id FROM users WHERE email = $1", [req.user.email]);
//             const uid = result.rows[0].user_id;
            
//             const groups = await db.query(`
//                 SELECT g.group_name, u.email AS created_by_email, g.group_id
//                 FROM group_members gm
//                 JOIN groups g ON gm.group_id = g.group_id
//                 JOIN users u ON g.created_by = u.user_id
//                 WHERE gm.user_id = $1
//                 ORDER BY g.group_name
//             `, [uid]);
            
//             console.log("User groups:", groups.rows);
//             res.render("group_list.ejs", { groups: groups.rows });
//         } catch (err) {
//             console.error("Error fetching groups:", err);
//             res.render("group_list.ejs", { groups: [] });
//         }
//     } else {
//         res.redirect("/sign-up");
//     }
// });

// app.get("/group/:group_name", async (req, res) => {
//     if (!req.isAuthenticated()) {
//         return res.redirect("/sign-up");
//     }

//     try {
//         const { group_name } = req.params;

//         const groupResult = await db.query(
//             `SELECT g.group_id, g.group_name, g.created_by, u.email AS created_by_email, u.username AS created_by_username
//              FROM groups g
//              JOIN users u ON g.created_by = u.user_id
//              WHERE g.group_name = $1`,
//             [group_name]
//         );

//         if (groupResult.rows.length === 0) {
//             return res.status(404).send("Group not found");
//         }

//         const group = groupResult.rows[0];

//         // Check if current user is a member
//         const memberCheck = await db.query(
//             "SELECT * FROM group_members WHERE group_id = $1 AND user_id = $2",
//             [group.group_id, req.user.user_id]
//         );

//         if (memberCheck.rows.length === 0) {
//             req.flash("error", "You are not a member of this group.");
//             return res.redirect("/groups_list");
//         }

//         const membersResult = await db.query(
//             `SELECT u.user_id, u.username, u.email, gm.role
//              FROM users u
//              JOIN group_members gm ON u.user_id = gm.user_id
//              WHERE gm.group_id = $1
//              ORDER BY u.username`,
//             [group.group_id]
//         );

//         const members = membersResult.rows.map(member => ({
//             ...member,
//             isAdmin: member.user_id === group.created_by
//         }));

//         const isUserAdmin = req.user.user_id === group.created_by;

//         res.render("group.ejs", {
//             group_name: group.group_name,
//             group_id: group.group_id,
//             created_by_email: group.created_by_email,
//             created_by_username: group.created_by_username,
//             members,
//             isUserAdmin,
//             message: req.flash("success")[0] || req.flash("error")[0] || null
//         });

//     } catch (err) {
//         console.error("Error loading group page:", err);
//         res.status(500).send("Server error");
//     }
// });

// // Interests selection page
// app.get("/interests", async (req, res) => {
//     if (!req.isAuthenticated()) {
//         return res.redirect("/sign-up");
//     }

//     const groupId = req.query.group_id;
//     if (!groupId) {
//         return res.redirect("/groups_list");
//     }

//     try {
//         const groupDetails = await getGroupDetails(groupId);
//         if (!groupDetails) {
//             req.flash("error", "Group not found.");
//             return res.redirect("/groups_list");
//         }

//         res.render("interests.ejs", {
//             group: groupDetails
//         });
//     } catch (err) {
//         console.error("Error loading interests page:", err);
//         res.redirect("/groups_list");
//     }
// });

// app.post("/interests", async (req, res) => {
//     if (!req.isAuthenticated()) {
//         return res.redirect("/sign-up");
//     }

//     const groupId = req.body.group_id;
//     const selectedInterests = req.body.interests || [];
    
//     try {
//         // Here you could save user interests to database if needed
//         console.log(`User ${req.user.email} selected interests:`, selectedInterests);
        
//         const groupDetails = await getGroupDetails(groupId);
//         if (groupDetails) {
//             req.flash("success", "Welcome to the group! Your interests have been saved.");
//             return res.redirect(`/group/${encodeURIComponent(groupDetails.group_name)}`);
//         }
        
//         res.redirect("/groups_list");
//     } catch (err) {
//         console.error("Error saving interests:", err);
//         res.redirect("/groups_list");
//     }
// });

// // SendGrid setup
// sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// app.post("/invite", async (req, res) => {
//     if (!req.isAuthenticated()) {
//         return res.redirect("/sign-up");
//     }

//     try {
//         const groupName = req.body.group_name;
//         const inviterEmail = req.user.email;
//         const inviterUsername = req.user.username;
//         const inviteeEmail = req.body.email;

//         if (!groupName || !inviteeEmail) {
//             req.flash("error", "Group name and email are required.");
//             return res.redirect(`/group/${encodeURIComponent(groupName)}`);
//         }

//         const groupResult = await db.query(
//             "SELECT group_id, created_by FROM groups WHERE group_name = $1",
//             [groupName]
//         );

//         if (groupResult.rows.length === 0) {
//             req.flash("error", "Group not found.");
//             return res.redirect("/groups_list");
//         }

//         const group = groupResult.rows[0];

//         // Check if user is admin of this group
//         if (group.created_by !== req.user.user_id) {
//             req.flash("error", "Only group admins can send invites.");
//             return res.redirect(`/group/${encodeURIComponent(groupName)}`);
//         }

//         // Check if invitee is already a member
//         const existingMember = await db.query(
//             `SELECT u.email FROM users u
//              JOIN group_members gm ON u.user_id = gm.user_id
//              WHERE gm.group_id = $1 AND u.email = $2`,
//             [group.group_id, inviteeEmail]
//         );

//         if (existingMember.rows.length > 0) {
//             req.flash("error", "User is already a member of this group.");
//             return res.redirect(`/group/${encodeURIComponent(groupName)}`);
//         }

//         const inviteLink = `http://localhost:3000/join?group_id=${group.group_id}&email=${encodeURIComponent(inviteeEmail)}`;

//         const msg = {
//             to: inviteeEmail,
//             from: process.env.EMAIL_USER,
//             subject: `${inviterUsername} invited you to join Smart Explorer!`,
//             html: `
//                 <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif;">
//                     <h2 style="color: #333;">You're Invited to Smart Explorer!</h2>
//                     <p><strong>${inviterUsername}</strong> has invited you to join their group "<strong>${groupName}</strong>" in Smart Explorer.</p>
//                     <p>Smart Explorer helps you plan amazing trips with your friends and discover new places together.</p>
//                     <div style="text-align: center; margin: 30px 0;">
//                         <a href="${inviteLink}" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Join Group</a>
//                     </div>
//                     <p style="color: #666; font-size: 14px;">If you can't click the button, copy this link: ${inviteLink}</p>
//                 </div>
//             `
//         };

//         await sgMail.send(msg);
//         req.flash("success", "Invitation sent successfully!");

//     } catch (error) {
//         console.error("SendGrid Error:", error);
//         req.flash("error", "Failed to send invitation email.");
//     }

//     const groupName = req.body.group_name;
//     if (groupName) {
//         return res.redirect(`/group/${encodeURIComponent(groupName)}`);
//     }
//     res.redirect("/groups_list");
// });

// // Create new group
// app.post("/create-group", async (req, res) => {
//     if (!req.isAuthenticated()) {
//         return res.redirect("/sign-up");
//     }

//     try {
//         const { group_name } = req.body;
        
//         if (!group_name || group_name.trim().length === 0) {
//             req.flash("error", "Group name is required.");
//             return res.redirect("/groups_list");
//         }

//         // Check if group name already exists
//         const existingGroup = await db.query(
//             "SELECT group_id FROM groups WHERE group_name = $1",
//             [group_name.trim()]
//         );

//         if (existingGroup.rows.length > 0) {
//             req.flash("error", "A group with this name already exists.");
//             return res.redirect("/groups_list");
//         }

//         // Create the group
//         const newGroup = await db.query(
//             "INSERT INTO groups (group_name, created_by) VALUES ($1, $2) RETURNING *",
//             [group_name.trim(), req.user.user_id]
//         );

//         const groupId = newGroup.rows[0].group_id;

//         // Add creator as admin member
//         await db.query(
//             "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, $3)",
//             [groupId, req.user.user_id, "admin"]
//         );

//         req.flash("success", "Group created successfully!");
//         return res.redirect(`/group/${encodeURIComponent(group_name.trim())}`);

//     } catch (err) {
//         console.error("Error creating group:", err);
//         req.flash("error", "Failed to create group.");
//         res.redirect("/groups_list");
//     }
// });

// Passport configuration
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