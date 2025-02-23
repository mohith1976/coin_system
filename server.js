const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
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

// ✅ User Schema & Model
const UserSchema = new mongoose.Schema({
  userId: { type: String, unique: true, required: true },
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  phone: { type: String, unique: true, required: true }, // ✅ Store without verification
  coins: { type: Number, default: 50 },
  lastLogin: { type: String, required: true },
  bonusClicks: { type: Number, default: 0 }
});

const User = mongoose.model('User', UserSchema);

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
    const { username, password, email, phone, otp } = req.body;

    if (!otpStore.has(email) || otpStore.get(email) !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }
    otpStore.delete(email);

    // Check if user exists
    let existingUser = await User.findOne({ $or: [{ username }, { email }, { phone }] });
    if (existingUser) {
      return res.status(400).json({ message: "Username, email, or phone already taken" });
    }

    // Hash password & generate User ID
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = crypto.randomUUID();

    const newUser = new User({
      userId,
      username,
      password: hashedPassword,
      email,
      phone, // ✅ Store without verification
      coins: 0,
      lastLogin: "null",
      bonusClicks: 0
    });

    await newUser.save();
    res.json({ message: "User registered successfully. Please log in." });

  } catch (err) {
    console.error("❌ Error in /register:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Middleware to Verify Token
const authenticateUser = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Unauthorized: Invalid token" });
    }
    req.username = decoded.username;
    next();
  });
};

// ✅ LOGIN API (Authenticate User)
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    let user = await User.findOne({ username });

    if (!user) {
      return res.status(400).json({ message: "User not found. Please register." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    let today = new Date().toISOString().split('T')[0];
    if (user.lastLogin !== today) {
      user.coins += 50;
      user.lastLogin = today;
      user.bonusClicks = 0;
      await user.save();
    }

    const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: "7d" });
    res.json({ message: "Login successful", token, user });

  } catch (err) {
    console.error("❌ Error in /login:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Protected API: Bonus Coins
app.post('/add-coins', authenticateUser, async (req, res) => {
  try {
    const { coins } = req.body;
    let user = await User.findOne({ username: req.username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.bonusClicks >= 5) {
      return res.status(400).json({ message: "No bonus attempts left today" });
    }

    user.coins += coins;
    user.bonusClicks += 1;
    await user.save();

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


// ✅ Update Profile API (Protected)
app.put('/update-profile', authenticateUser, async (req, res) => {
  try {
    const { email, phone } = req.body;

    // 🔹 Check if email or phone is already used by another user
    let existingUser = await User.findOne({ 
      $or: [{ email }, { phone }],
      username: { $ne: req.username } // 🔹 Ensure it's not the same user
    });

    if (existingUser) {
      return res.status(400).json({ message: "Email or phone number is already taken" });
    }

    // 🔹 Update user profile
    let user = await User.findOneAndUpdate(
      { username: req.username },
      { email, phone },
      { new: true }
    ).select("-password"); // 🔹 Exclude password

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

// ✅ Check Backend Status
app.get("/", (req, res) => {
  res.send("Backend is running! 🚀");
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running on port ${PORT}`));
