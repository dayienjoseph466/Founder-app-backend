// server/models/Admin.js
const mongoose = require("mongoose");

const AdminSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },
    // hidden by default, use .select("+passwordHash") when you need it
    passwordHash: { type: String, required: true, select: false }
  },
  { timestamps: true, versionKey: false }
);

// make sure the unique index exists
AdminSchema.index({ email: 1 }, { unique: true });

// do not send passwordHash in API responses
AdminSchema.set("toJSON", {
  transform(_doc, ret) {
    delete ret.passwordHash;
    return ret;
  }
});

module.exports = mongoose.models.Admin || mongoose.model("Admin", AdminSchema);
