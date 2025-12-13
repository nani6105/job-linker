const mongoose = require('mongoose');

const applicationSchema = new mongoose.Schema({
    jobId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Job' },
    studentName: { type: String, required: true },
    studentEmail: { type: String, required: true },
    phoneNumber: { type: String },
    resume: { type: String }, // PDF file path
    status: { type: String, default: 'pending', enum: ['pending', 'accepted', 'rejected'] },
    appliedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Application', applicationSchema);
