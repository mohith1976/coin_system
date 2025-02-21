const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // ✅ Hash passwords securely
const jwt = require('jsonwebtoken'); // ✅ Generate authentication tokens
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Ensure MongoDB URI is Set
const mongoURI = process.env.MONGO_URI;
if (!mongoURI) {
  console.error("❌ MONGO_URI is not set in .env file or Render environment variables.");
  process.exit(1);
}

// ✅ Connect to MongoDB Atlas
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
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }, // ✅ Store hashed password
  coins: { type: Number, default: 50 },
  lastLogin: { type: String, required: true },
  bonusClicks: { type: Number, default: 0 } // ✅ Track bonus attempts per user
});

const User = mongoose.model('User', UserSchema);

// ✅ REGISTER API (New User Signup)
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 🔹 Check if user already exists
    let existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already taken" });
    }

    // 🔹 Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ 
      username, 
      password: hashedPassword, 
      lastLogin: new Date().toISOString().split('T')[0],
      bonusClicks: 0 // ✅ Ensure bonusClicks is initialized
    });

    await newUser.save();
    res.json({ message: "User registered successfully. Please log in." });

  } catch (err) {
    console.error("❌ Error in /register:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ LOGIN API (Authenticate User & Give Daily Bonus)
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log(`🔍 Checking user in MongoDB: ${username}`);

    let user = await User.findOne({ username });

    // 🔹 Check if user exists
    if (!user) {
      return res.status(400).json({ message: "User not found. Please register." });
    }

    // 🔹 Validate password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // 🔹 Grant daily login bonus if it's a new day
    let today = new Date().toISOString().split('T')[0];
    if (user.lastLogin !== today) {
      user.coins += 50;
      user.lastLogin = today;
      user.bonusClicks = 0;  // ✅ Reset bonus clicks each day
      await user.save();
    }

    // 🔹 Generate authentication token
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({ message: "Login successful", token, user });

  } catch (err) {
    console.error("❌ Error in /login:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ BONUS COINS API (Click Bonus)
app.post('/add-coins', async (req, res) => {
  try {
    const { username, coins } = req.body;
    console.log(`🔍 Adding ${coins} coins to: ${username}`);

    let user = await User.findOne({ username });
    if (!user) {
      console.log("❌ User not found for bonus.");
      return res.status(404).json({ message: "User not found" });
    }

    if (user.bonusClicks >= 5) {
      console.log(`❌ User ${username} has used all bonus attempts today.`);
      return res.status(400).json({ message: "No bonus attempts left today" });
    }

    user.coins += coins;
    user.bonusClicks += 1;  // ✅ Track bonus clicks per user
    await user.save();

    console.log(`✅ Coins updated for ${username}: ${user.coins}, Bonus Clicks: ${user.bonusClicks}`);
    res.json({ message: "Coins updated", user });

  } catch (err) {
    console.error("❌ Error in /add-coins:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ CHECK BACKEND STATUS
app.get("/", (req, res) => {
  res.send("Backend is running! 🚀");
});

// ✅ Fix Port Issue for Render
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running on port ${PORT}`));
