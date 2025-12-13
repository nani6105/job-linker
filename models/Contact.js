const mongoose = require("mongoose");

const ContactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  reply: { type: String, default: "" },
  repliedAt: { type: Date, default: null },
}, { timestamps: true });

module.exports = mongoose.model("Contact", ContactSchema);
