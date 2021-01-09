import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import mongoose from 'mongoose';
import crypto from 'crypto';
import bcrypt from 'bcrypt-nodejs';

const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/auth"
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
mongoose.Promise = Promise

const User = mongoose.model('User', {
  name: {
    type: String,
    unique: true
  },
  email: {
    type: String,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString('hex')
  }
});

const authenticateUser = async (req, res, next) => {
  const user = await User.findOne({ accessToken: req.header('Authorization') });
  if (user) {
    req.user = user;
    next();
  } else {
    res.status(401).json({ loggedOut: true })
  }
}

//   PORT=9000 npm start
const port = process.env.PORT || 8080
const app = express()

// Add middlewares to enable cors and json body parsing
app.use(cors())
app.use(bodyParser.json())

// Start defining your routes here
app.get('/', (req, res) => {
  res.send('Hello world')
})

// Registration endpoint
app.post('/users', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    // DO NOT store plaintext passwords
    const user = new User({ name, email, password: bcrypt.hashSync(password) });
    // Saves user to the database
    user.save();
    res.status(201).json({ id: user._id, accessToken: user.accessToken });
  } catch (err) {
    res.status(400).json({ message: 'Could not create user', errors: err.errors });
  }
});

// Need to authenticate user first to see if user is logged in, 
// if yes the get request executes
app.get('/secrets', authenticateUser);
app.get('/secrets', (req, res) => {
  res.json({ secret: 'This is a super secret message' });
});

// Possibility for the user to log in
app.post('/sessions', async (req, res) => {
  // User to log in with email - to be checked in the database
  const user = await User.findOne({ email: req.body.email });
  if (user && bcrypt.compareSync(req.body.password, user.password)) {
    res.json({ userId: user._id, accessToken: user.accessToken });
  } else {
    res.json({ notFound: true });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
