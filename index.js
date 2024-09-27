import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypto from "bcrypt";
import crypto from "crypto";
import nodemailer from "nodemailer";
import 'dotenv/config';
// import config from "./config.json" with { type: "json" };

const app = express();
const port = 3000;
const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "comunication_ltd",
    password: process.env.PG_PASS,
    port: 5432,
});
let forgot_email = "";
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.set('view engine', 'ejs');

function generateResetToken() {
  const randomValue = crypto.randomBytes(20).toString('hex'); // Generate random value
  const token = crypto.createHash('sha1').update(randomValue).digest('hex'); // Hash it using SHA-1
  return token;
}

app.get('/', (req, res) => {
    res.render("enterPage.ejs",{
        passError:"",
    });
});

app.get('/register', (req, res) => {
    res.render('register.ejs');
});

app.get("/packege", (req, res) => {
    res.render("packege.ejs");
});

app.get("/forgotPass", (req, res) => {
  res.render("forgotPass.ejs",{
    just_text:"No worries, we'll send you reset instructions.",
    step:1
});
});



app.post("/register", async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
       
   try{const check = await db.query(
      "select * from users where email = $1",
      [email]
    );

    if (check.rows.length >0){

      res.send("email alredy exists!!!");
    }else{

      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = await bcrypto.hash(password + salt, 10);
      const result = await db.query(
        "insert into users (username, password_hash, email, salt) values ($1 , $2, $3, $4)",
        [username, passwordHash, email, salt]
      );
      console.log(result);
      res.render("register.ejs");
    };
    } catch(err){
      console.log(err);
    };
    
  });

app.post("/login", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  console.log(email);
  console.log(password);

  try{const check = await db.query(
    "select * from users where email = $1 ", 
    [email]
  );

  if(check.rows.length >0){
    const user = check.rows[0];

    if (user.account_locked) {
      res.render("forgotPass.ejs",{
        just_text:"Account is locked, Please reset youre password",
        step:1
    });
    }

    const hashedPassword = await bcrypto.hash(password + user.salt, 10);
    console.log(hashedPassword);
    console.log(user);

    const match = await bcrypto.compare(password + user.salt, user.password_hash);

    if (match) {
      await db.query("UPDATE users SET failed_attempts = 0, account_locked = FALSE WHERE email = $1", [email]);
      res.render("packege.ejs");
 
    }else{
      const failedAttempts = user.failed_attempts + 1;

        if (failedAttempts >= 3) {
          await db.query("UPDATE users SET failed_attempts = $1, account_locked = TRUE WHERE email = $2", 
            [failedAttempts, email]);

            res.render("forgotPass.ejs",{
              just_text:"Account is locked after 3 failed login attempts. Please reset your password.",
              step:1
            
            });

          }else{
            await db.query("UPDATE users SET failed_attempts = $1 WHERE email = $2", [failedAttempts, email]);   
            res.render("enterPage.ejs",{
              passError:"the email or the password is incorrect"
            });
          }
    }
    
    console.log("im here");

  }else{
    res.render("enterPage.ejs",{
      passError:"the email or the password is incorrect"
    });  }
    }catch(err){
      console.log(err);
    }
});

app.post("/forgotPass", async (req, res) => {
  const email = req.body.email;
  forgot_email = email;
  try {
    // Find user by email
    const check = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (check.rows.length > 0) {
      const user = check.rows[0];
      const resetToken = generateResetToken(); // Generate reset token
      const resetTokenExpiration = new Date(Date.now() + 3600000); // Token expires in 1 hour

      // Store the token and expiration time in the database
      await db.query("insert into reset_pass (reset_token, reset_token_expiration, user_email) values ($1, $2, $3)",
        [resetToken, resetTokenExpiration, email]);

      // Send email with reset token
      const transporter = nodemailer.createTransport({
        service: 'gmail', // Use your email service
        host: "smtp.gmail.com",
        port:465,
        secure: true,
        auth: {
          user: process.env.GMAIL,
          pass: process.env.GMAIL_PASS
        }
      });

      const mailOptions = {
        from: process.env.GMAIL,
        to: email,
        subject: 'Password Reset',
        text: `You requested a password reset. Please use the following token to reset your password: ${resetToken}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return console.log(error);
        }
        res.render("forgotPass.ejs",{
          just_text:"An email with a reset token has been sent to your email address.",
          step: 2,
          email:email,
        });
      });

    } else {
      // If the email does not exist in the database
      res.send("Email not found.");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("An error occurred. Please try again.");
  }
});

app.get("/reset-password",(req,res)=>{
  res.render("forgotPass.ejs",{
    just_text:"An email with a reset token has been sent to your email address.",
    step: 2
  })
})

app.post("/reset-password", async (req, res) => {
  const email = forgot_email;
  const resetToken = req.body.token;
  console.log(email);
  
  try {
    // Fetch the user by email and check the token
    const check = await db.query(
      "SELECT * FROM reset_pass WHERE user_email = $1 AND reset_token = $2 AND reset_token_expiration > NOW()",
      [email, resetToken]
    );

    if (check.rows.length > 0) {
      // Token is valid and not expired, direct the user to the reset password page
      await db.query(
        "delete from reset_pass where reset_token = $1", [resetToken]
      );
      res.render("forgotPass.ejs", { email: email,
        just_text:"",
        step: 3
       });
    } else {
      // Invalid or expired token
      res.send("Invalid or expired token. Please try again.");
    }

  } catch (err) {
    console.error(err);
    res.status(500).send("An error occurred. Please try again.");
  }
});

app.get("/update-password", (req, res)=>{
  res.render("forgotPass.ejs",{
    just_text:"",
    step: 3
  })
});

app.post("/update-password", async (req, res) => {
  const email = forgot_email;
  const newPassword = req.body.password;

  try {
    // Fetch the user by email
    const check = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (check.rows.length > 0) {
      const user = check.rows[0];
      const salt = user.salt;
      const hashedPassword = await bcrypto.hash(newPassword + salt, 10);

      // Update the password and clear the reset token
      await db.query("UPDATE users SET password_hash = $1, failed_attempts = 0, account_locked = false WHERE email = $2",
        [hashedPassword, email]);

      res.redirect("/");

    } else {
      res.send("User not found.");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("An error occurred. Please try again.");
  }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);  
});
  