const mongoose = require("mongoose");

// ✅ User Schema & Model
const UserSchema = new mongoose.Schema({
  userId: { type: String, unique: true, required: true },
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  phone: { type: String, unique: true, required: true }, // ✅ Store without verification
  coins: { type: Number, default: 50 },
  lastLogin: { type: String, required: true },
  bonusClicks: { type: Number, default: 0 },
  otp: { type: String },  // ✅ Store OTP in the database
  otpExpires: { type: Date }, // ✅ Expiry time for OTP (e.g., 10 mins)
  referralCode: { type: String, unique: true, required: true },  // ✅ New Field
  referredBy: { type: String, default: null }, // ✅ Stores the referral code of the referrer
  dailyStreak: { type: Number, default: 0 }, 
  lastCheckInDate: { type: String, default: "" },
  currentToken: { type: String } // ✅ Store latest login token

});

const User = mongoose.model('User', UserSchema);
module.exports = User;