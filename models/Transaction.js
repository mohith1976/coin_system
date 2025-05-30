const mongoose = require("mongoose");

// ✅ Define Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  amount: { type: Number, required: true },
  type: { type: String, enum: ["earn", "spend"], required: true },
  reason: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const Transaction = mongoose.model("Transaction", transactionSchema);

module.exports = Transaction;