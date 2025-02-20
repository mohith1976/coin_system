const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// Define a User Schema
const UserSchema = new mongoose.Schema({
    username: String,
    coins: { type: Number, default: 50 },
    lastLogin: String
});

const User = mongoose.model('User', UserSchema);

// API to create a new user (login simulation)
app.post('/login', async (req, res) => {
    const { username } = req.body;
    let today = new Date().toISOString().split('T')[0];

    let user = await User.findOne({ username });

    if (!user) {
        user = new User({ username, lastLogin: today });
        await user.save();
        return res.json({ message: "User created", user });
    }

    if (user.lastLogin !== today) {
        user.coins += 50;
        user.lastLogin = today;
        await user.save();
    }

    res.json({ message: "User logged in", user });
});

// API to add coins (Bonus Click)
app.post('/add-coins', async (req, res) => {
    const { username, coins } = req.body;

    let user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: "User not found" });

    user.coins += coins;
    await user.save();

    res.json({ message: "Coins updated", user });
});

// Start Server (Change 'localhost' to '0.0.0.0')
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
