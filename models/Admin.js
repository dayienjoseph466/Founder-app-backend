// server/models/Admin.js
const mongoose = require("mongoose");

const AdminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
}, { timestamps: true });

module.exports = mongoose.models.Admin || mongoose.model("Admin", AdminSchema);
