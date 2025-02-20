const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config(); // ✅ Load .env file

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Connect to MongoDB Atlas using .env
const mongoURI = process.env.MONGO_URI;
if (!mongoURI) {
  console.error("❌ MONGO_URI is not set in .env file or Render environment variables.");
  process.exit(1); // Stop server if MONGO_URI is missing
}

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB Connected Successfully"))
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
  username: String,
  coins: { type: Number, default: 50 },
  lastLogin: String
});

const User = mongoose.model('User', UserSchema);

// ✅ Login API (User Registration & Daily Login Bonus)
app.post('/login', async (req, res) => {
  try {
    const { username } = req.body;
    let today = new Date().toISOString().split('T')[0];

    let user = await User.findOne({ username });

    if (!user) {
      user = new User({ username, lastLogin: today });
      await user.save();
      return res.json({ message: "User created", user });
    }

    if (user.lastLogin !== today) {
      user.coins += 50; // Daily Login Bonus
      user.lastLogin = today;
      await user.save();
    }

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

    let user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: "User not found" });

    user.coins += coins;
    await user.save();

    res.json({ message: "Coins updated", user });

  } catch (err) {
    console.error("❌ Error in /add-coins:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Fix Port Issue for Render
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running on port ${PORT}`));
