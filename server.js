const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
require('dotenv').config();

// Sử dụng port từ biến môi trường hoặc mặc định là 5000 (cho local development)
const port = process.env.PORT || 5000;

// Cấu hình CORS
const allowedOrigins = [
  'http://localhost:3000', 
  process.env.FRONTEND_URL, 
].filter(Boolean); 

app.use(cors({
  credentials: true,
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
}));
app.use(express.json());
app.use(cookieParser());

// Kiểm tra các biến môi trường
const requiredEnvVars = ['MONGODB_USERNAME', 'MONGODB_PASSWORD', 'MONGODB_DATABASE', 'MONGODB_CLUSTER', 'JWT_SECRET'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Error: Missing environment variable ${envVar}`);
    process.exit(1);
  }
}

// Tạo chuỗi kết nối MongoDB từ các biến môi trường
const MONGODB_URI = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_CLUSTER}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority&appName=Cluster0`;


// Kết nối MongoDB Atlas
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB Atlas');
    console.log('Using database:', mongoose.connection.db.databaseName);
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Schema và Model cho Counters (để tự động tăng id)
const CounterSchema = new mongoose.Schema({
  _id: String,
  sequence_value: Number,
});
const Counter = mongoose.model('Counter', CounterSchema);

// Schema và Model cho Shoes
const ShoeSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  name: String,
  image: String,
  price: Number,
  type: String,
  color: String,
  attribute: String,
}, { collection: 'Shoes' });
const Shoe = mongoose.model('Shoe', ShoeSchema);

// Schema và Model cho Users
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
}, { collection: 'Users' });
const User = mongoose.model('User', UserSchema);

// Secret key cho JWT
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware kiểm tra token
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Token required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Hàm lấy và tăng giá trị id, đảm bảo không trùng
const getNextSequenceValue = async (sequenceName) => {
  try {
    let sequenceDoc;
    let newId;

    do {
      sequenceDoc = await Counter.findOneAndUpdate(
        { _id: sequenceName },
        { $inc: { sequence_value: 1 } },
        { new: true, upsert: true }
      );
      newId = sequenceDoc.sequence_value;

      const existingShoe = await Shoe.findOne({ id: newId });
      if (existingShoe) {
        console.log(`ID ${newId} already exists, trying next ID...`);
      } else {
        break;
      }
    } while (true);

    return newId;
  } catch (error) {
    throw new Error('Error getting sequence value: ' + error.message);
  }
};

// Đăng ký
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error registering user: ' + error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, {
      expiresIn: '1h',
    });

    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
    res.json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ error: 'Error logging in: ' + error.message });
  }
});

// Đăng xuất
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

app.get('/shoes', authenticateToken, async (req, res) => {
  try {
    console.log('Database used:', mongoose.connection.db.databaseName);
    const shoes = await Shoe.find();
    res.json({ shoes });
  } catch (error) {
    console.log('Error fetching shoes:', error);
    res.status(500).json({ error: 'Error fetching shoes: ' + error.message });
  }
});

// Thêm giày mới (Nhóm 3-4: Add Data)
app.post('/shoes', authenticateToken, async (req, res) => {
  try {
    const { name, image, price, type, color, attribute } = req.body;
    const id = await getNextSequenceValue('shoe_id');
    const newShoe = new Shoe({ id, name, image, price, type, color, attribute });
    await newShoe.save();
    res.status(201).json({ message: 'Shoe added successfully', shoe: newShoe });
  } catch (error) {
    res.status(500).json({ error: 'Error adding shoe: ' + error.message });
  }
});

app.put('/shoes/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, image, price, type, color, attribute } = req.body;
    const updatedShoe = await Shoe.findByIdAndUpdate(
      id,
      { name, image, price, type, color, attribute },
      { new: true }
    );
    if (!updatedShoe) {
      return res.status(404).json({ error: 'Shoe not found' });
    }
    res.json({ message: 'Shoe updated successfully', shoe: updatedShoe });
  } catch (error) {
    res.status(500).json({ error: 'Error updating shoe: ' + error.message });
  }
});

// Khởi động server
app.listen(port, () => {
  console.log(`Example app listening on port ${port}!`);
});