import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypto from "bcrypt";
import crypto from "crypto";
import nodemailer from "nodemailer";
import 'dotenv/config';
// import expressLayouts from "express-ejs-layouts";
import cookieParser from "cookie-parser";
import { error } from "console";
// import config from "./config.json" with { type: "json" };


const app = express();
// app.use(expressLayouts);
const port = 3000;
app.use(cookieParser());
const db = new pg.Client({
    user: "postgres",
    host: "16.170.245.106",
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

async function updatePassword(useremail, newPassword) {
  const user = await db.query("SELECT password_history, password_hash, salt FROM users WHERE email = $1", [useremail]);
  const passwordHistory = user.rows[0].password_history || [];
  const currentHashedPassword = user.rows[0].password_hash;
  const salt = user.rows[0].salt;
  console.log(salt);
  console.log(passwordHistory);


  const newHashedPassword = await bcrypto.hash(newPassword+salt,10);

  const isSameAsCurrent = await bcrypto.compare(newPassword + salt, currentHashedPassword);

  if (isSameAsCurrent) {
    // If the new password matches the current password, reject it
    return false;
  }

  // Check if the new password matches any in the password history
  for (const oldHashedPassword of passwordHistory) {
    const isSameAsHistory = await bcrypto.compare(newPassword + salt, oldHashedPassword);
    if (isSameAsHistory) {
      // If the new password matches any of the old passwords, reject it
      return false;
    }
  }

  passwordHistory.push(newHashedPassword);
  
  if (passwordHistory.length > 3) {
    passwordHistory.shift();
  }

  await db.query(
    "UPDATE users SET password_hash = $1, password_history = $2 WHERE email = $3",
    [newHashedPassword, passwordHistory, useremail]
  );

  console.log("Password updated successfully!");
  return true;
}

app.get('/', (req, res) => {
    res.render("enterPage.ejs",{
        passError:"",
    });
});

app.get('/innerPage', async (req, res) => {
  const newCustomer = req.cookies.newCustomer || null;
  const user_name = await db.query('select username from users where email = $1',[newCustomer]);
  console
  if(user_name.rows.length > 0){
    res.render('innerPage.ejs', { 
    title: 'Page Title',
    body: 'Some content for the body',
    customer: user_name.rows[0].username, 
  });
} else{
  res.redirect("/enterPage.ejs");
}
});

app.get("/change-password", async (req,res) =>{
  res.render("forgotPass",{
    error:null,
    success: null,
    step:5,
  })
})

app.get('/register', (req, res) => {
    res.render('register.ejs');
});

app.get("/packege", (req, res) => {
    res.render("layout.ejs");
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

    console.log(user.username);

    const match = await bcrypto.compare(password + user.salt, user.password_hash);

    if (match) {
      await db.query("UPDATE users SET failed_attempts = 0, account_locked = FALSE WHERE email = $1", [email]);
      res.cookie('newCustomer', user.email, { maxAge: 900000, httpOnly: true });
      res.redirect("/innerPage");
 
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
    const check = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (check.rows.length > 0) {
      const user = check.rows[0];
      const resetToken = generateResetToken(); 
      const resetTokenExpiration = new Date(Date.now() + 360000); 

      await db.query("insert into reset_pass (reset_token, reset_token_expiration, user_email) values ($1, $2, $3)",
        [resetToken, resetTokenExpiration, email]);

      const transporter = nodemailer.createTransport({
        service: 'gmail', 
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
      res.render("forgotPass.ejs",{
        just_text:"Email not found.",
        step: 1,
        email:email,
      });
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
    const check = await db.query(
      "SELECT * FROM reset_pass WHERE user_email = $1 AND reset_token = $2 AND reset_token_expiration > NOW()",
      [email, resetToken]
    );

    if (check.rows.length > 0) {
      await db.query(
        "delete from reset_pass where reset_token = $1", [resetToken]
      );
      res.render("forgotPass.ejs", { email: email,
        just_text:"",
        step: 3
       });
    } else {
      res.render("forgotPass.ejs", { email: email,
        just_text:"Invalid or expired token. Please try again.",
        step: 1
       });
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
    const check = await updatePassword(email, newPassword);
    if (check) {
      res.render("forgotPass.ejs",{
        step: 4,
      })

    } else {
      res.render("forgotPass.ejs",{
        just_text:"You cannot reuse your previous passwords.",
        step: 3,
      })
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("An error occurred. Please try again.");
  }
});

app.post('/change-password', async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;

  // Assuming user ID is stored in the session or passed in some way
  const email = req.cookies.newCustomer;

  try {
      const user = await db.query('SELECT password_hash, salt, password_history FROM users WHERE email = $1', [email]);
      
      if (!user.rows.length) {
          return res.render('forgotPass.ejs', { 
            error: 'User not found, please re`enter',
            success: null,
            step: 5,

          });
      }

      const { password_hash, salt, password_history } = user.rows[0];

      // Step a: Verify the current password
      const isPasswordCorrect = await bcrypto.compare(currentPassword + salt, password_hash);
      if (!isPasswordCorrect) {
          return res.render('forgotPass.ejs', { 
            error: 'Current password is incorrect',
            success: null,
            step: 5,

          });
        }

      // Step b: Check if new password meets requirements
      if (newPassword !== confirmPassword) {
          return res.render('forgotPass.ejs', { 
            error: 'New passwords do not match',
            success: null,
            step: 5,

          });
        }

    

      // Step c: Check if the new password was used recently
      const newHashedPassword = await bcrypto.hash(newPassword + salt, 10);

      const passwordHistory = password_history || [];
      for (const oldPasswordHash of passwordHistory) {
          const isSameAsOld = await bcrypto.compare(newPassword + salt, oldPasswordHash);
          if (isSameAsOld) {
              return res.render('forgotPass.ejs', { 
                error: 'Cannot reuse a recent password',
                success: null,
                step: 5,
    
              });
            }
      }

      // Step d: Update the password and history
      const updatedPasswordHistory = [...passwordHistory.slice(-2), password_hash]; // Keep last 3 passwords
      await db.query('UPDATE users SET password_hash = $1, password_history = $2 WHERE email = $3', [
          newHashedPassword,
          updatedPasswordHistory,
          email
      ]);

      res.render('forgotPass.ejs', { error: null, success: 'Password changed successfully', step: 5 });
  } catch (error) {
      console.error(error);
      res.render('forgotPass.ejs', { error: 'An error occurred', success: null, step:5 });
  }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);  
});
  
