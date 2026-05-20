const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  targetUrl: {
    type: String,
    required: [true, 'Please provide a target URL'],
    trim: true,
  },
  score: {
    type: Number,
    min: 0,
    max: 100,
    default: 0,
  },
  severity: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low'],
    default: 'Low',
  },
  vulnerabilities: {
    type: [
      {
        name: { type: String },
        description: { type: String },
        severity: { type: String, enum: ['Critical', 'High', 'Medium', 'Low'] },
      },
    ],
    default: [],
  },
  scannedAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('Scan', scanSchema);
