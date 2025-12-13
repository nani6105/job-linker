const mongoose = require('mongoose');

const JobSchema = new mongoose.Schema({
    company: { type: String, required: true },
    title: { type: String, required: true },
    course: { type: String, required: true },
    description: { type: String, required: true },
    employerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

module.exports = mongoose.model('Job', JobSchema);
