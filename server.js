const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config(); // ✅ Load .env file

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Ensure MongoDB URI is Set
const mongoURI = process.env.MONGO_URI;
if (!mongoURI) {
  console.error("❌ MONGO_URI is not set in .env file or Render environment variables.");
  process.exit(1); // Stop server if MONGO_URI is missing
}

// ✅ Connect to MongoDB Atlas with Explicit Database Name
mongoose.connect(mongoURI, {
  dbName: "flutter_app", // Force MongoDB to use "flutter_app" database
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB Connected to flutter_app"))
.catch(err => {
  console.error("❌ MongoDB Connection Error:", err);
  process.exit(1);
});

// ✅ Default Route (Check If Backend is Running)
app.get("/", (req, res) => {
  res.send("Backend is running! 🚀");
});

// ✅ User Schema & Model
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  coins: { type: Number, default: 50 },
  lastLogin: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

// ✅ Login API (Create User & Give Daily Bonus)
app.post('/login', async (req, res) => {
  try {
    const { username } = req.body;
    console.log(`🔍 Checking user in MongoDB: ${username}`);

    let today = new Date().toISOString().split('T')[0];
    let user = await User.findOne({ username });

    if (!user) {
      console.log("🆕 Creating new user...");
      user = new User({ username, lastLogin: today });
      await user.save();
      console.log("✅ New user saved in MongoDB:", user);
      return res.json({ message: "User created", user });
    }

    if (user.lastLogin !== today) {
      console.log("🎉 Daily login bonus granted!");
      user.coins += 50;
      user.lastLogin = today;
      await user.save();
    }

    console.log("✅ User login successful:", user);
    res.json({ message: "User logged in", user });

  } catch (err) {
    console.error("❌ Error in /login:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Bonus Coins API (Click Bonus)
app.post('/add-coins', async (req, res) => {
  try {
    const { username, coins } = req.body;
    console.log(`🔍 Adding ${coins} coins to: ${username}`);

    let user = await User.findOne({ username });
    if (!user) {
      console.log("❌ User not found for bonus.");
      return res.status(404).json({ message: "User not found" });
    }

    user.coins += coins;
    await user.save();

    console.log(`✅ Coins updated for ${username}: ${user.coins}`);
    res.json({ message: "Coins updated", user });

  } catch (err) {
    console.error("❌ Error in /add-coins:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Fix Port Issue for Render
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running on port ${PORT}`));
