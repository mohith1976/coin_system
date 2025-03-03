const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const cron = require("node-cron");
const User = require("./models/User");
const Transaction = require("./models/Transaction");
const CentralPool = require("./models/CentralPool");

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer'); // ✅ Only Email OTP
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Load and Validate Environment Variables
const mongoURI = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;
const emailUser = process.env.EMAIL_USER;
const emailPass = process.env.EMAIL_PASS;

if (!mongoURI || !jwtSecret || !emailUser || !emailPass) {
  console.error("❌ ERROR: Missing required environment variables!");
  process.exit(1);
}

// ✅ Connect to MongoDB
mongoose.connect(mongoURI, {
  dbName: "flutter_app",
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch(err => {
    console.error("❌ MongoDB Connection Error:", err);
    process.exit(1);
  });






const logTransaction = async (user, amount, reason, type) => {
  try {
    const transaction = new Transaction({
      userId: user._id, // ✅ Corrected: Use user._id
      amount,
      reason,
      type, // ✅ Added: Ensure type ("earn" or "spend") is logged
      timestamp: new Date()
    });
    await transaction.save();
  } catch (err) {
    console.error("❌ Error logging transaction:", err);
  }
};

// ✅ OTP Storage
const otpStore = new Map();

// ✅ Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: emailUser,
    pass: emailPass
  }
});

// ✅ Send OTP via Email
async function sendOTP(email) {
  const otp = crypto.randomInt(100000, 999999).toString();
  otpStore.set(email, otp);

  // Send Email
  await transporter.sendMail({
    from: emailUser,
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP is: ${otp}`
  });

  return otp;
}

// ✅ REQUEST OTP API (Check for Duplicate Email & Phone First)
app.post('/request-otp', async (req, res) => {
  try {
    const { email, phone } = req.body;

    // 🔹 Check if email or phone already exists
    let existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      return res.status(400).json({ message: "Email or phone number is already registered" });
    }

    // 🔹 Send OTP if email & phone are not already used
    await sendOTP(email, phone);
    res.json({ message: "OTP sent successfully" });

  } catch (err) {
    console.error("❌ Error in /request-otp:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ REGISTER API (New User Signup with OTP)
app.post('/register', async (req, res) => {
  try {
    const { username, password, email, phone, otp, referralCode } = req.body;

    // ✅ Validate OTP
    if (!otpStore.has(email) || otpStore.get(email) !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }
    otpStore.delete(email);

    // ✅ Check if user already exists
    let existingUser = await User.findOne({ $or: [{ username }, { email }, { phone }] });
    if (existingUser) {
      return res.status(400).json({ message: "Username, email, or phone already taken" });
    }

    // ✅ Generate Referral Code (6-character random)
    const userReferralCode = Math.random().toString(36).substring(2, 8).toUpperCase();

    // ✅ Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = crypto.randomUUID();

    const newUser = new User({
      userId,
      username,
      password: hashedPassword,
      email,
      phone,
      coins: 50,  // ✅ Default 50 coins
      lastLogin: "null",
      bonusClicks: 0,
      referralCode: userReferralCode, // ✅ Store user’s unique referral code
      referredBy: null
    });

    // ✅ Handle Referral Bonus
    if (referralCode) {
      let referrer = await User.findOne({ referralCode });
      if (referrer) {
        newUser.referredBy = referralCode;
        newUser.coins += 25; // ✅ New user gets 25 extra coins
        referrer.coins += 50; // ✅ Referrer gets 50 coins
        await referrer.save();
        await logTransaction(newUser, 25, "Referred by another user", "earn"); 
        await logTransaction(referrer, 50, "Referral bonus", "earn"); 
      }
    }

    await newUser.save();
    res.json({ message: "User registered successfully!", referralCode: userReferralCode });

  } catch (err) {
    console.error("❌ Error in /register:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// ✅ Middleware to Verify Token
const authenticateUser = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    const user = await User.findOne({ username: decoded.username });

    // ✅ Ensure token matches the latest one stored in DB
    if (!user || user.currentToken !== token) {
      return res.status(403).json({ message: "Session expired. Please log in again." });
    }

    req.username = decoded.username;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Unauthorized: Invalid token" });
  }
};

// ✅ LOGIN API (Authenticate User)
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    let user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: "User not found. Please register." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    let today = new Date().toISOString().split('T')[0];

    if (user.lastLogin !== today) {
      let pool = await CentralPool.findOne();
      if (!pool || pool.totalCoins < 50) {
        return res.status(400).json({ message: "Daily login bonus unavailable (insufficient pool balance)" });
      }

      user.coins += 50;
      user.lastLogin = today;
      user.bonusClicks = 0;
      pool.totalCoins -= 50; // Deduct from pool
      await pool.save();
      await user.save();
      await logTransaction(user, 50, "Daily login bonus", "earn"); 
    }

    // ✅ Generate token & store in DB to track sessions
    const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: "7d" });
    user.currentToken = token;
    await user.save();

    res.json({ message: "Login successful", token, user });

  } catch (err) {
    console.error("❌ Error in /login:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Check Daily Login & Add Coins if Needed
app.post('/daily-login', authenticateUser, async (req, res) => {
  try {
    let user = await User.findOne({ username: req.username });
    if (!user) return res.status(404).json({ message: "User not found" });

    let today = new Date().toISOString().split('T')[0];

    if (user.lastLogin !== today) {
      let pool = await CentralPool.findOne();
      if (!pool || pool.totalCoins < 50) {
        return res.status(400).json({ message: "Daily login bonus unavailable (insufficient pool balance)" });
      }

      user.coins += 50;
      user.lastLogin = today;
      user.bonusClicks = 0;
      pool.totalCoins -= 50;
      await pool.save();
      await user.save();
      await logTransaction(user, 50, "Daily login bonus", "earn");  
    }

    res.json({ message: "Daily login bonus added", user });

  } catch (err) {
    console.error("❌ Error in /daily-login:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ LOGOUT API
app.post('/logout', authenticateUser, async (req, res) => {
  try {
    await User.findOneAndUpdate(
      { username: req.username },
      { $unset: { currentToken: "" } } // ✅ Remove token from DB
    );

    res.json({ message: "Logged out successfully." });
  } catch (err) {
    console.error("❌ Error in /logout:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// ✅ DAILY CHECK-IN BONUS API
app.post('/daily-checkin', authenticateUser, async (req, res) => {
  try {
      let user = await User.findOne({ username: req.username });
      if (!user) return res.status(404).json({ message: "User not found" });

      const today = new Date().toISOString().split('T')[0];

      if (user.lastCheckInDate === today) {
          return res.status(400).json({ message: "Already checked in today!" });
      }

      let newStreak = user.dailyStreak + 1; // Increase streak
      if (newStreak > 7) newStreak = 1; // Reset after 7 days

      // If user missed a day, reset streak to 1
      const lastCheckIn = new Date(user.lastCheckInDate);
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      if (user.lastCheckInDate && lastCheckIn.toISOString().split('T')[0] !== yesterday.toISOString().split('T')[0]) {
          newStreak = 1; // Reset streak if user missed a day
      }

      // Daily coin rewards based on streak
      const dailyRewards = [0, 10, 20, 30, 40, 50, 60, 70]; // Index 1-7 (0 is unused)
      const coinsToAdd = dailyRewards[newStreak];

      let pool = await CentralPool.findOne();
      if (!pool || pool.totalCoins < coinsToAdd) {
          return res.status(400).json({ message: "Check-in bonus unavailable (insufficient pool balance)" });
      }

      user.coins += coinsToAdd;
      user.dailyStreak = newStreak;
      user.lastCheckInDate = today;
      pool.totalCoins -= coinsToAdd;
      await pool.save();
      await user.save();
      await logTransaction(user, coinsToAdd, `Daily check-in streak ${newStreak}`, "earn");

      res.json({
          message: `Daily check-in successful! You received ${coinsToAdd} coins.`,
          user
      });

  } catch (err) {
      console.error("❌ Error in /daily-checkin:", err);
      res.status(500).json({ message: "Server error" });
  }
});

// ✅ Update Central Pool Balance (Existing Model)
const updateCentralPool = async (amount) => {
  try {
    let pool = await CentralPool.findOne();

    if (!pool) {
      console.error("❌ Central Pool not found! Creating one.");
      pool = new CentralPool({ totalCoins: 50000000 }); // ✅ Create if missing
    }

    pool.totalCoins += amount; // ✅ Add spent coins to pool
    pool.lastUpdated = new Date();
    await pool.save();

    console.log(`✅ Central Pool Updated: +${amount} Coins | New Balance: ${pool.totalCoins}`);
  } catch (err) {
    console.error("❌ Error updating Central Pool:", err);
  }
};
// ✅ Premium Access API (Deducts 50 Coins & Grants 2 Hours Access)
app.post('/premium-access', authenticateUser, async (req, res) => {
  try {
    let user = await User.findOne({ username: req.username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // ✅ Check if user has enough coins
    if (user.coins < 50) {
      return res.status(400).json({ message: "Not enough coins for premium access!" });
    }

    // ✅ Deduct 50 coins from user
    user.coins -= 50;

    // ✅ Add deducted coins to Central Pool (Existing Model)
    await updateCentralPool(50); // ✅ Coins go to pool

    // ✅ Set Premium Access Expiry (2 Hours)
    user.premiumExpiry = new Date(Date.now() + 2 * 60 * 60 * 1000);
    await user.save();

    // ✅ Log the transaction
    await logTransaction(user, 50, "Premium access purchase", "spend");

    res.json({ message: "Premium access granted for 2 hours!", premiumExpiry: user.premiumExpiry });

  } catch (err) {
    console.error("❌ Error in /premium-access:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// ✅ Check if user still has Premium Access
app.get('/check-premium-access', authenticateUser, async (req, res) => {
  try {
    let user = await User.findOne({ username: req.username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // ✅ If user has active premium access
    const now = new Date();
    if (user.premiumExpiry && user.premiumExpiry > now) {
      return res.json({ accessGranted: true, expiresAt: user.premiumExpiry });
    }

    res.json({ accessGranted: false, message: "Premium access expired! Spend 50 coins to re-enter." });

  } catch (err) {
    console.error("❌ Error in /check-premium-access:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ FORGOT PASSWORD: Request OTP
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    let user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // ✅ OTP expires in 10 minutes

    // ✅ Always update OTP and expiration in database
    await User.updateOne(
      { email },
      { $set: { otp, otpExpires } }
    );

    // Send OTP via Email
    await transporter.sendMail({
      from: emailUser,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP for password reset is: ${otp}. This OTP expires in 10 minutes.`,
    });

    res.json({ message: "OTP sent to your email." });

  } catch (err) {
    console.error("❌ Error in /forgot-password:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ RESET PASSWORD AFTER OTP VERIFICATION
app.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    let user = await User.findOne({ email });

    // ✅ Ensure OTP exists and is valid
    if (!user || !user.otp || user.otp.toString() !== otp || new Date() > user.otpExpires) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // ✅ Prevent reusing the same password
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ message: "You cannot use the same old password." });
    }

    // ✅ Hash new password **before modifying OTP**
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // ✅ Update password & clear OTP in a **single database update**
    await User.updateOne(
      { email, otp }, // Ensure we only modify if OTP still matches
      { 
        $set: { password: hashedPassword },
        $unset: { otp: 1, otpExpires: 1 } // ✅ Ensures OTP is removed only after success
      }
    );

    res.json({ message: "Password reset successfully. You can now log in." });

  } catch (err) {
    console.error("❌ Error in /reset-password:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ GET TOP 10 USERS FOR LEADERBOARD
app.get('/leaderboard', async (req, res) => {
  try {
    const topUsers = await User.find({})
      .sort({ coins: -1 }) // Sort by coins in descending order
      .limit(10) // Get top 10 users
      .select("username coins"); // Select only necessary fields

    res.json({ leaderboard: topUsers });
  } catch (err) {
    console.error("❌ Error in /leaderboard:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// ✅ Get Referral Info API
app.get('/referral-info', authenticateUser, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // ✅ Find all users who used this user's referral code
    const referredUsers = await User.find({ referredBy: user.referralCode });

    // ✅ Calculate total earnings from referrals
    let totalEarnings = 0;
    const formattedReferredUsers = referredUsers.map((referredUser) => {
      const earnedCoins = 50; // Coins earned per referral
      totalEarnings += earnedCoins;
      return {
        username: referredUser.username,
        earnedCoins,
      };
    });

    res.json({
      referralCode: user.referralCode,
      totalReferrals: referredUsers.length,
      totalEarnings,
      referredUsers: formattedReferredUsers,
    });

  } catch (err) {
    console.error("❌ Error in /referral-info:", err);
    res.status(500).json({ message: "Server error" });
  }
});


cron.schedule("0 0 * * *", async () => {
  try {
    await User.updateMany({}, { $set: { bonusClicks: 0 } });
    console.log("✅ Bonus click limits reset for all users.");
  } catch (err) {
    console.error("❌ Error resetting bonus clicks:", err);
  }
});

// ✅ Protected API: Bonus Coins
app.post('/add-coins', authenticateUser, async (req, res) => {
  try {
    const { coins } = req.body;
    let user = await User.findOne({ username: req.username });

    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.bonusClicks >= 5) {
      return res.status(400).json({ message: "No bonus attempts left today" });
    }

    let pool = await CentralPool.findOne();
    if (!pool || pool.totalCoins < coins) {
        return res.status(400).json({ message: "Ad bonus unavailable (insufficient pool balance)" });
    }

    user.coins += coins;
    user.bonusClicks += 1;
    pool.totalCoins -= coins;
    await pool.save();
    await user.save();
    
    await logTransaction(user, coins, "Daily ad bonus", "earn");  

    res.json({ message: "Coins updated", user });

  } catch (err) {
    console.error("❌ Error in /add-coins:", err);
    res.status(500).json({ message: "Server error" });
  }
});



// ✅ View User Profile API (Protected)
app.get('/profile', authenticateUser, async (req, res) => {
  try {
    let user = await User.findOne({ username: req.username }).select("-password"); // 🔹 Exclude password
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User profile fetched", user });
  } catch (err) {
    console.error("❌ Error in /profile:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// ✅ Request OTP for Email Update
app.post('/request-email-otp', authenticateUser, async (req, res) => {
  try {
    const { newEmail } = req.body;
    
    // 🔹 Check if email is already in use
    let emailExists = await User.findOne({ email: newEmail });
    if (emailExists) {
      return res.status(400).json({ message: "Email is already in use" });
    }

    // 🔹 Generate OTP and store it
    const otp = crypto.randomInt(100000, 999999).toString();
    otpStore.set(newEmail, otp);

    // 🔹 Send OTP via email
    await transporter.sendMail({
      from: emailUser,
      to: newEmail,
      subject: "Email Verification OTP",
      text: `Your OTP for email update is: ${otp}`
    });

    console.log(`✅ OTP sent to new email: ${newEmail}`);
    res.json({ message: "OTP sent to new email" });

  } catch (err) {
    console.error("❌ Error in /request-email-otp:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// ✅ Update Profile API (Protected)
app.put('/update-profile', authenticateUser, async (req, res) => {
  try {
    const { email, phone, otp } = req.body;

    let user = await User.findOne({ username: req.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // 🔹 Prevent updating to the same email or phone
    if (email === user.email && phone === user.phone) {
      return res.status(400).json({ message: "You cannot update to the same old email or phone." });
    }

    // 🔹 Check if the new email or phone is already used by another user
    if (email && email !== user.email) {
      let emailExists = await User.findOne({ email });
      if (emailExists) return res.status(400).json({ message: "Email is already in use." });

      // 🔹 Verify OTP for email change
      if (!otpStore.has(email) || otpStore.get(email) !== otp) {
        return res.status(400).json({ message: "Invalid OTP for email verification" });
      }
      otpStore.delete(email);
    }

    if (phone && phone !== user.phone) {
      let phoneExists = await User.findOne({ phone });
      if (phoneExists) return res.status(400).json({ message: "Phone number is already in use." });
    }

    // 🔹 Update user profile
    if (email) user.email = email;
    if (phone) user.phone = phone;

    await user.save();

    res.json({ message: "Profile updated successfully", user });

  } catch (err) {
    console.error("❌ Error in /update-profile:", err);
    res.status(500).json({ message: "Server error" });
  }
});



// ✅ Change Password API (Protected)
app.put('/change-password', authenticateUser, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    let user = await User.findOne({ username: req.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // 🔹 Validate old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect old password" });
    }

    // 🔹 Prevent changing to the same old password
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ message: "You cannot use the same old password." });
    }

    // 🔹 Hash new password and update
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: "Password changed successfully" });

  } catch (err) {
    console.error("❌ Error in /change-password:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// ✅ Delete Account API (Protected)
app.delete('/delete-account', authenticateUser, async (req, res) => {
  try {
    let user = await User.findOneAndDelete({ username: req.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "Account deleted successfully" });

  } catch (err) {
    console.error("❌ Error in /delete-account:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get('/transaction-history', authenticateUser, async (req, res) => {
  try {
    // ✅ Fetch user details based on username
    const user = await User.findOne({ username: req.username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userId = user._id; // ✅ Get correct user ID

    // ✅ Fetch transactions from the last 10 days
    const tenDaysAgo = new Date();
    tenDaysAgo.setDate(tenDaysAgo.getDate() - 10);

    const transactions = await Transaction.find({
      userId: userId, // ✅ Use correct user ID
      timestamp: { $gte: tenDaysAgo }
    }).sort({ timestamp: -1 });

    console.log("✅ Fetched Transactions:", transactions);
    res.json({ transactions });

  } catch (err) {
    console.error("❌ Error in /transaction-history:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// ✅ Auto-Delete Old Transactions (Runs Every Day)
cron.schedule("0 0 * * *", async () => {
  try {
    const tenDaysAgo = new Date();
    tenDaysAgo.setDate(tenDaysAgo.getDate() - 10);
    await Transaction.deleteMany({ timestamp: { $lt: tenDaysAgo } });
    console.log("🗑 Old transactions deleted.");
  } catch (err) {
    console.error("❌ Error deleting old transactions:", err);
  }
});
// ✅ Fetch User Data API
app.get('/fetch-user', authenticateUser, async (req, res) => {
  try {
    let user = await User.findOne({ username: req.username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User data fetched", user });

  } catch (err) {
    console.error("❌ Error in /fetch-user:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Auto-Refill Pool (Runs Every Hour)
cron.schedule("0 * * * *", async () => {
  const pool = await CentralPool.findOne();
  const initialSupply = 50000000; // Initial pool balance

  if (pool.totalCoins < initialSupply * 0.5) {
    pool.totalCoins += initialSupply * 0.25; // Refill 25% of initial supply
    pool.lastUpdated = new Date();
    await pool.save();
    console.log("🚀 Auto-refilled central pool by 25%.");
  }
});

cron.schedule("0 * * * *", async () => {
  const pool = await CentralPool.findOne();
  const initialSupply = 50000000;

  if (pool.totalCoins < initialSupply * 0.5) {
    console.log("⚠️ ALERT: Pool is below 50%. Admin needs to take action!");
  }
});


// ✅ Check Backend Status
app.get("/", (req, res) => {
  res.send("Backend is running! 🚀");
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running on port ${PORT}`));
