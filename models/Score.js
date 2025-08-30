const mongoose = require("mongoose");

const ScoreSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true, required: true },
    date: { type: String, index: true, required: true },

    // NEW: number of verified tasks for that date
    tasksDone: { type: Number, default: 0 },

    // We’ll keep these for backward compatibility (set to 0 now)
    rawPoints: { type: Number, default: 0 },
    proofBonus: { type: Number, default: 0 },
    verifyBonus: { type: Number, default: 0 },

    // Total points for the day (now = tasksDone * 5)
    total: { type: Number, default: 0 },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Score", ScoreSchema);
