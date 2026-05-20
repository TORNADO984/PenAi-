const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const { notFound, errorHandler } = require('./middleware/errorMiddleware');

// Load environment variables
dotenv.config();

// Connect to MongoDB
connectDB();

const app = express();

// ---------- Middleware ----------

// Enable CORS for all origins (frontend can connect from any port)
app.use(cors());

// Parse incoming JSON payloads
app.use(express.json());

// Parse URL-encoded payloads
app.use(express.urlencoded({ extended: false }));

// ---------- Health-check Route ----------

app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to PenAI API 🛡️',
    status: 'running',
    version: '1.0.0',
  });
});

// ---------- API Routes ----------

app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/scans', require('./routes/scanRoutes'));

// ---------- Error Handling Middleware ----------

app.use(notFound);
app.use(errorHandler);

// ---------- Start Server ----------

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 PenAI server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
});
