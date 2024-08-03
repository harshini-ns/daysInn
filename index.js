let express = require('express');
let path = require('path');
const cors = require('cors');
const { Pool } = require('pg');
const { DATABASE_URL , SECRET_KEY} = process.env
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

let app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    require: true,
  },
});

async function getPostgresVersion() {
  const client = await pool.connect();

  try {
    const response = await client.query('SELECT version()');
    console.log(response.rows[0]);
  } finally {
    client.release();
  }
}

getPostgresVersion();

/**
 * ADD YOUR ENDPOINT HERE
 */

//sign up endpoint
app.post('/signup', async (req, res) => {
  const client = await pool.connect();
  try {
    const { email, password, phoneNumber, profilePicture } = req.body;

    
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
//sql query added
    const userResult = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length > 0) {
      return res.status(400).json({ message: "Email is already taken" });
    }
    await client.query(
      'INSERT INTO users (email, password, phoneNumber, profilePicture) VALUES ($1, $2, $3, $4)',
      [email, hashedPassword, phoneNumber || null, profilePicture || null]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error during user registration:", error.message);
    res.status(500).json({
      error: "An error occurred during user registration",
      details: error.message
    });
  } finally {
    client.release();
  }
});


///
//log in endpoint 
app.post('/login', async (req, res) => {
  const client = await pool.connect();
  try {
    const { email, password } = req.body;

    
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }
    const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ message: "Email or password is incorrect" });
    }

    // Comparing the password from frontend(user)with the hashed password in database
    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).json({ auth: false, token: null, message: "Email or password is incorrect" });
    }

    // JWT token
    const token = jwt.sign({ user_id: user.user_id, email: user.email }, SECRET_KEY, { expiresIn: 86400 });

    res.status(200).json({ auth: true, token: token , message : "User logged in successfully" });
  } catch (error) {
    console.error("Error during user login", error.message);
    res.status(500).json({ error: "An error occurred during user login", details: error.message });
  } finally {
    client.release();
  }
});





/**
 * ADD YOUR ENDPOINT HERE 
 */

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname + '/index.html'))
});

app.listen(4000, () => {
  console.log('App is listening on port 3000');
})