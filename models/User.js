const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['student', 'employer', 'admin'] },

    // Student-specific fields
    fullName: { type: String },
    collegeName: { type: String },
    course: { type: String },
    branch: { type: String },
    phoneNumber: { type: String },

    // Employer-specific fields
    companyName: { type: String }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
