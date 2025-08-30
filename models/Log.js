// server/models/Log.js
const mongoose = require("mongoose");

const logSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    taskId: { type: mongoose.Schema.Types.ObjectId, ref: "Task", required: true },
    date: { type: String, required: true }, // keep YYYY-MM-DD string
    note: { type: String, required: true },
    proofUrl: { type: String, required: true },
    status: { type: String, enum: ["PENDING", "VERIFIED", "REJECTED"], default: "PENDING" },
    // IMPORTANT: increments on every resubmission so reviewers see it again
    reviewRound: { type: Number, default: 1 },
  },
  { timestamps: true }
);

logSchema.index({ userId: 1, taskId: 1, date: 1 }, { unique: true });

module.exports = mongoose.model("Log", logSchema);
