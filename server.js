const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB Connection
const connectDB = async () => {
  try {
    console.log('🔄 Attempting to connect to MongoDB...');
    console.log(`🔗 Connection URI: ${process.env.MONGODB_URI?.replace(/:[^:]*@/, ':***@')}`);
    
    const conn = await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ MongoDB Connected Successfully!');
    console.log(`📍 Database: ${conn.connection.name}`);
    console.log(`🌐 Host: ${conn.connection.host}`);
    console.log(`🔌 Port: ${conn.connection.port}`);
    console.log(`🔒 Connection State: ${conn.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
  } catch (error) {
    console.error('❌ MongoDB Connection Failed:', error.message);
    
    // More specific error handling
    if (error.message.includes('IP')) {
      console.error('� IP Whitelist Issue: Add your IP to MongoDB Atlas whitelist');
      console.error('📖 Guide: https://www.mongodb.com/docs/atlas/security-whitelist/');
    } else if (error.message.includes('authentication')) {
      console.error('🔐 Authentication Issue: Check username/password in MONGODB_URI');
    } else if (error.message.includes('ENOTFOUND')) {
      console.error('🌐 Network Issue: Check your internet connection and URI format');
    }
    
    console.error('�🔧 Please check your MONGODB_URI in .env file');
    console.error('💡 For local development, you can use: mongodb://localhost:27017/OnlyAssets');
    process.exit(1);
  }
};

// Connect to MongoDB
connectDB();

// MongoDB connection event listeners
mongoose.connection.on('connected', () => {
  console.log('🟢 Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('🔴 Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('🟡 Mongoose disconnected from MongoDB');
});

// Handle app termination
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('🔴 MongoDB connection closed due to app termination');
  process.exit(0);
});

app.use(cors());
app.use(express.json());

// Import routes
const authRoutes = require('./routes/authRouter');

// Use routes
app.use('/auth', authRoutes);

app.get('/', (req, res) => {
  res.send('API is working');
});

app.listen(PORT, () => {
  console.log('🚀 =================================');
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV}`);
  console.log(`🔗 API URL: http://localhost:${PORT}`);
  console.log('🚀 =================================');
});
