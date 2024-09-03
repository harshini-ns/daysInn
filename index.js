let express = require("express");
let path = require("path");
const cors = require("cors");
const { Pool } = require("pg");
const { DATABASE_URL, SECRET_KEY } = process.env;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

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
    const response = await client.query("SELECT version()");
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
app.post("/signup", async (req, res) => {
  const client = await pool.connect();
  try {
    const { email, password, phone_number, profile_picture } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    //sql query added
    const userResult = await client.query(
      "SELECT * FROM users WHERE email = $1",
      [email],
    );
    if (userResult.rows.length > 0) {
      return res.status(400).json({ message: "Email is already taken" });
    }
    await client.query(
      "INSERT INTO users (email, password, phone_number, profile_picture) VALUES ($1, $2, $3, $4)",
      [email, hashedPassword, phone_number || null, profile_picture || null],
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error during user registration:", error.message);
    res.status(500).json({
      error: "An error occurred during user registration",
      details: error.message,
    });
  } finally {
    client.release();
  }
});

///
//log in endpoint
app.post("/login", async (req, res) => {
  const client = await pool.connect();
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }
    const result = await client.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user) {
      return res
        .status(400)
        .json({ message: "Email or password is incorrect" });
    }

    // Comparing the password from frontend(user)with the hashed password in database
    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).json({
        auth: false,
        token: null,
        message: "Email or password is incorrect",
      });
    }

    // JWT token
    const token = jwt.sign(
      { user_id: user.user_id, email: user.email },
      SECRET_KEY,
      { expiresIn: 86400 },
    );

    res.status(200).json({
      auth: true,
      token: token,
      message: "User logged in successfully",
    });
  } catch (error) {
    console.error("Error during user login", error.message);
    res.status(500).json({
      error: "An error occurred during user login",
      details: error.message,
    });
  } finally {
    client.release();
  }
});

//create a booking API endpoint => POST

app.post("/bookings", async (req, res) => {
  const token = req.headers["authorization"];
  console.log("Token received in backend:", token);

  if (!token) {
    return res.status(403).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user_id = decoded.user_id;
  } catch (error) {
    return res
      .status(403)
      .json({ error: "Failed to authenticate token", details: error.message });
  }

  const client = await pool.connect();
  try {
    const { hotel_id, start_date, end_date } = req.body;
    const user_id = req.user_id; // using the user_id from the decoded token

    const result = await client.query(
      "INSERT INTO bookings (user_id, hotel_id, start_date, end_date, created_time, updated_time) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING *",
      [user_id, hotel_id, start_date, end_date],
    );
    const newBooking = result.rows[0];
    res
      .status(201)
      .json({ message: "Booking created successfully", booking: newBooking });
  } catch (error) {
    console.error("Error creating booking:", error.message);
    res.status(500).json({
      error: "An error occurred while creating the booking",
      details: error.message,
    });
  } finally {
    client.release();
  }
});

//
//get all bookings of a specific user
app.get("/bookings", async (req, res) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(403).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user_id = decoded.user_id;
  } catch (error) {
    return res.status(500).json({ error: "Failed to authenticate token" });
  }
  //
  const client = await pool.connect();
  try {
    const result = await client.query(
      "SELECT * FROM bookings WHERE user_id = $1",
      [req.user_id],
    );
    const bookings = result.rows;
    res
      .status(200)
      .json({ message: "Bookings retrieved successfully", bookings: bookings });
  } catch (error) {
    console.error("Error retrieving bookings:", error.message);
    res.status(500).json({
      error: "An error occurred while retrieving the bookings",
      details: error.message,
    });
  } finally {
    client.release();
  }
});

//
//update a booking

app.put("/bookings/:booking_id", async (req, res) => {
  //jwt token
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ error: "No token provided" });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user_id = decoded.user_id;
  } catch (error) {
    return res.status(500).json({ error: "Failed to authenticate token" });
  }

  //verificaton ends here
  //now logic
  const { booking_id } = req.params; //  booking_id from route parameters and other details from request body
  const { hotel_id, start_date, end_date } = req.body;
  const client = await pool.connect();
  try {
    //if the booking exists and belongs to the user
    const checkBooking = await client.query(
      "SELECT * FROM bookings WHERE booking_id=$1 AND user_id=$2",
      [booking_id, req.user_id],
    );
    if (checkBooking.rows.length == 0) {
      return res.status(404).json({ error: "booking not found" });
    }
    //update logic
    const result = await client.query(
      " UPDATE bookings SET hotel_id=$1, start_date=$2, end_date=$3 , updated_time=CURRENT_TIMESTAMP WHERE booking_id=$4 RETURNING *",
      [hotel_id, start_date, end_date, booking_id],
    );

    const updatedBooking = result.rows[0];
    res.status(200).json({
      message: " booking updated successfully",
      booking: updatedBooking,
    });
  } catch (error) {
    console.error("error in updating booking", error.message);
    res
      .status(500)
      .json({ error: " error in booking update", details: error.message });
  } finally {
    client.release();
  }
});
//

//delete a booking
app.delete("/bookings/:booking_id", async (req, res) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ error: "No token provided" });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user_id = decoded.user_id;
  } catch (error) {
    return res.status(500).json({ error: "Failed to authenticate token" });
  }
  //
  const { booking_id } = req.params;
  const client = await pool.connect();
  try {
    const checkBooking = await client.query(
      "SELECT * FROM bookings WHERE booking_id=$1 AND user_id=$2",
      [booking_id, req.user_id],
    );
    if (checkBooking.rows.length == 0) {
      return res.status(404).json({ error: "booking not found" });
    }
    await client.query("DELETE FROM bookings WHERE booking_id=$1 RETURNING *", [
      booking_id,
    ]);
    res.status(200).json({ message: "booking deleted successfully" });
  } catch (error) {
    console.error("Error in deleting booking", error.message);
    res
      .status(500)
      .json({ error: "Error in booking deletion", details: error.message });
  } finally {
    client.release();
  }
});
//
//get all hotels API
app.get("/hotels", async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query("SELECT * FROM hotels");
    const hotels = result.rows || [];
    res
      .status(200)
      .json({ message: "hotels retrieved successfully", hotels: hotels });
  } catch (error) {
    console.error("error in retrieving hotels", error.message);
    res
      .status(500)
      .json({ error: "error in retrieving hotels", details: error.message });
  } finally {
    client.release();
  }
});
//
//get holtels by id
app.get("/hotels/:hotel_id", async (req, res) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(403).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user_id = decoded.user_id;

    const client = await pool.connect();

    try {
      const result = await client.query(
        "SELECT * FROM hotels WHERE hotel_id = $1",
        [req.params.hotel_id],
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Hotel not found" });
      }
      res.status(200).json(result.rows[0]);
    } catch (error) {
      console.error("error in retrieving hotel by id ", error.message);
      res
        .status(500)
        .json({
          error: "error in retrieving hotels by id",
          details: error.message,
        });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("Error verifying token", error);
    return res.status(500).json({ error: "Failed to authenticate token" });
  }
});

//user update (PUT) their own User profile->email, password, phone_number, profile_picture
app.put("/userUpdate", async (req, res) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ error: "No token provided" });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user_id = decoded.user_id;
  } catch (error) {
    return res.status(500).json({ error: "Failed to authenticate token" });
  }
  //
  const { email, password, phone_number, profile_picture } = req.body;
  const client = await pool.connect();
  try {
    const result = await client.query(
      "UPDATE users SET email=$1, password=$2 , phone_number=$3, profile_picture=$4 WHERE user_id=$5 RETURNING *",
      [email, password, phone_number, profile_picture, req.user_id],
    );

    const updatedUser = result.rows[0];
    res.status(200).json({
      message: "user profile updated successfully",
      user: updatedUser,
    });
  } catch (error) {
    console.error(error.message, "error in updating user data");
    res
      .status(400)
      .json({ error: "error in user update", details: error.message });
  } finally {
    client.release();
  }
});


//get user details in profile page 
//profilepage 

// Endpoint to get user details after login
app.get("/user/profile", async (req, res) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(403).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user_id = decoded.user_id;

    const client = await pool.connect();

    try {
      const result = await client.query(
        "SELECT user_id, email, phone_number, profile_picture FROM users WHERE user_id = $1",
        [req.user_id]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      res.status(200).json(result.rows[0]);
    } catch (error) {
      console.error("Error retrieving user details", error.message);
      res.status(500).json({
        error: "Error in retrieving user details",
        details: error.message,
      });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("Error verifying token", error);
    return res.status(500).json({ error: "Failed to authenticate token" });
  }
});



/**
 * ADD YOUR ENDPOINT HERE
 */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname + "/index.html"));
});

app.listen(4000, () => {
  console.log("App is listening on port 3000");
});
