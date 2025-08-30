const mongoose = require("mongoose");

const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  role: { type: String, enum: ["CEO","COO","MARKETING","ALL"], required: true },
  points: { type: Number, default: 5 },
  isActive: { type: Boolean, default: true }
});

module.exports = mongoose.model("Task", taskSchema);
