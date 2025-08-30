// server/models/Review.js
const mongoose = require("mongoose");

const reviewSchema = new mongoose.Schema(
  {
    logId: { type: mongoose.Schema.Types.ObjectId, ref: "Log", required: true },
    reviewerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    decision: { type: String, enum: ["APPROVE", "REJECT"], required: true },
    comment: { type: String, default: "" },
    // IMPORTANT: round is used to gate pending items after resubmissions
    round: { type: Number, required: true, default: 1 },
  },
  { timestamps: true }
);

// Prevent the same reviewer from reviewing the same log more than once in the same round
reviewSchema.index({ logId: 1, reviewerId: 1, round: 1 }, { unique: true });

module.exports = mongoose.model("Review", reviewSchema);
