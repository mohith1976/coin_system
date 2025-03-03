const mongoose = require("mongoose");

const centralPoolSchema = new mongoose.Schema({
  totalCoins: { type: Number, required: true, default: 50000000 }, // Initial supply
  lastUpdated: { type: Date, default: Date.now }
});

const CentralPool = mongoose.model("CentralPool", centralPoolSchema);
module.exports = CentralPool;
