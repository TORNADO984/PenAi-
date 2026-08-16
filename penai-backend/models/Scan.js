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
        severity: { type: String, enum: ['Critical', 'High', 'Medium', 'Low', 'Info'] },
        solution: { type: String },
        url: { type: String },
        aiRemediation: { type: Object },
      },
    ],
    default: [],
  },
  aiSummary: {
    type: Object,
  },
  status: {
    type: String,
    enum: ['pending', 'scanning', 'complete', 'failed'],
    default: 'pending',
  },
  progressMessage: {
    type: String,
    default: 'Initializing scan...',
  },
  progressPct: {
    type: Number,
    default: 0,
  },
  scanTime: {
    type: Number,
    default: 0,
  },
  scannedAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('Scan', scanSchema);
