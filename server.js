import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from 'dotenv';
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
import flash from "connect-flash";;
import nodemailer from "nodemailer"
// import GoogleStrategy from "passport-google-oauth2";


dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
	secret: "TOPSECRET",
	resave: false,
	saveUninitialized: true,
}));

app.use(flash());

app.use((req, res, next) => {
  res.locals.error = req.flash("error");
  res.locals.success = req.flash("success");
  next();
});

app.use(passport.initialize());
app.use(passport.session());


const db = new pg.Client({
	host: process.env.HOST,
	port: process.env.PORT,
	user: process.env.USER,
	password: process.env.PASSWORD,
	database: process.env.DATABASE,
});

(async () => {
	try {
		await db.connect();
		console.log("Connected to Postgres");
	}
	catch (err) {
		console.error("Database connection failed:", err);
		process.exit(1);
	}
})();

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));



// Routes
app.get("/", (req, res) => {
	res.render("index.ejs");
});

app.get("/sign-up", (req, res) => {
	res.render("sign-up.ejs");
});

app.get("/log-in", (req, res) => {
	res.render("log-in.ejs");
});

// Sign-up
app.post("/sign-up", async (req, res) => {
	const { username, email, password } = req.body;

	try {
	const checkResult = await db.query(
		"SELECT * FROM users WHERE email = $1",
		[email]
	);

	if (checkResult.rows.length > 0) {
		return res.render("sign-up.ejs", {err: "Email already exists, try logging in."});
	}

	if(password.length < 8){
		return res.render("sign-up.ejs", {passwordErr: "Password should be greater than 8 characters"})
	}

	const hash = await bcrypt.hash(password, saltRounds);

	await db.query(
		"INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
		[username, email, hash]
	);

	return res.render("home.ejs");
	} catch (err) {
		console.error("Sign-up error:", err);
		return res.status(500).send("Internal Server Error");
	}
});

// Log-in
app.post("/log-in",
	passport.authenticate("local", {
		successRedirect: "/home",
		failureRedirect: "/log-in",
		failureFlash: true
	})
);


// passport.use("google", new GoogleStrategy({
//   clientID: process.env.GOOGLE_CLIENT_ID,
//   clientSecret: process.env.GOOGLE_CLIENT_SECRET,
//   callbackURL: "http:localhost:3000/auth/google/secrets",
//   userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
// }), async(acessToken, refreshToken, profile, cb) => {
  
// })

// --------- INNER PAGES ---------- //



app.get("/home", (req, res) => {
	if(req.isAuthenticated()){
		res.render("home.ejs");
	}
	else{
		res.render("sign-up.ejs");
	}
})

app.get("/plan", (req, res) => {
	if(req.isAuthenticated()){
		res.render("plan.ejs");
	}
	else{
		res.render("sign-up.ejs");
	}
})

app.get("/group", (req, res) => {
	if(req.isAuthenticated()){
		res.render("group.ejs");
	}
	else{
		res.render("sign-up.ejs");
	}
})

app.get("/offline", (req, res) => {
	if(req.isAuthenticated()){
		res.render("offline.ejs");
	}
	else{
		res.render("sign-up.ejs");
	}
})

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) { return next(err); }
    req.flash("success", "You have logged out successfully.");
    res.redirect("/log-in");
  });
});

app.post("/generate-plan", (req, res) => {
	const place = req.body.place;
	const checkin = req.body.checkin;
	const checkout = req.body.checkout;
	const radius = req.body.radius;
	const customInterest = req.body["custom-interest"];
  	const selectedInterests = JSON.parse(req.body["selected-interests"] || "[]");
	console.log(place, checkin, checkout, radius, customInterest, selectedInterests);
	res.redirect("/home");
})

app.post("/invite", async (req, res) => {
	if(req.isAuthenticated()){
		console.log(req.user.email);
		const email = req.body.email;
		const inviter = req.user.email;

		try{
			let transporter = nodemailer.createTransport({
				service: "gmail",
				auth: {
					type: "OAuth2",
					user: process.env.EMAIL_USER,      // your Gmail address
					clientId: process.env.GOOGLE_CLIENT_ID,
					clientSecret: process.env.GOOGLE_CLIENT_SECRET,
					refreshToken: process.env.GOOGLE_USER_REFRESH_TOKEN,
				}
			});
			
			await transporter.sendMail({
				from: `"Smart Explorer" <${process.env.EMAIL_USER}>`,
				to: email,
				subject: `${inviter} invited you to join Smart Explorer!`,
				text: `Hey! ${inviter} invited you to plan a trip together on Smart Explorer. Click here to join.`,
				html: `<h3>You're Invited!</h3>
						<p><strong>${inviter}</strong> has invited you to join Smart Explorer.</p>
						<p>Click <a href='http://localhost:3000/join'>here</a> to join the group.</p>`
			});

			console.log(`Invitation sent to ${email} by ${inviter}`);
			res.render("group.ejs", {message: "Invitation sent!"});
		} 
		catch (error) {
			console.error(error);
			res.render("group.ejs", {message: "Failed to send invite."});
		}
	}
	else{
		res.render("sign-up.ejs");
	}
	

})


passport.use(new Strategy({
		usernameField: "email",
		passwordField: "password"
  	},
	async function verify(email, password, cb){
		try {
			const result = await db.query(
				"SELECT * FROM users WHERE email = $1",
				[email]
			);
			

			if (result.rows.length === 0) {
				return cb(null, false, { message: "User not found, please sign up." });
			}

			const user = result.rows[0];
			const matched = await bcrypt.compare(password, user.password_hash);
				if (matched) {
					return cb(null, user);
				}
				else {
					return cb(null, false, { message: "Incorrect Password. Please enter the right password." });
				}
		}
		catch (err) {
			cb(err);
		}
}));

passport.serializeUser((user, cb) => {
	cb(null, user);
})

passport.deserializeUser((user, cb) => {
	cb(null, user);
})

app.listen(port, () => {
	console.log(`Server running at port ${port}`);
});
