// server/models/Announcement.js
const mongoose = require("mongoose");

const CreatorSchema = new mongoose.Schema(
  {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    name: { type: String, trim: true },
    role: { type: String, enum: ["ADMIN", "CEO", "COO", "MARKETING", "USER"] },
  },
  { _id: false }
);

const AnnouncementSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 120 },
    body: { type: String, required: true, trim: true, maxlength: 4000 },
    audience: {
      type: [String], // e.g. ["ALL"] or ["CEO","COO","MARKETING"]
      default: ["ALL"],
      enum: ["ALL", "CEO", "COO", "MARKETING"],
    },
    pinned: { type: Boolean, default: false },
    expiresAt: { type: Date, default: null }, // optional
    // allow storing full creator snapshot as used by routes
    createdBy: { type: CreatorSchema, default: null },
  },
  { timestamps: true }
);

// Optional: auto delete when past expiresAt (null values are ignored by TTL)
AnnouncementSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("Announcement", AnnouncementSchema);
