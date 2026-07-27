const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const path = require('path');
const pool = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

// Serve the frontend files (index.html, driver-simulator.html, etc.) from this same server,
// so there's only one server/port to run and expose — instead of a separate http-server on 8080
app.use(express.static(path.join(__dirname, '..', 'frontend')));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

app.get('/', (req, res) => {
  res.send('Hitchhike backend is running');
});

app.get('/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ success: true, time: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { full_name, phone_number, email, password, role, vehicle } = req.body;

  if (!full_name || !phone_number || !password || !role) {
    return res.status(400).json({ error: 'full_name, phone_number, password, and role are required' });
  }
  if (!['rider', 'driver', 'both'].includes(role)) {
    return res.status(400).json({ error: 'role must be rider, driver, or both' });
  }

  try {
    const existing = await pool.query(
      'SELECT id FROM users WHERE phone_number = $1 OR (email IS NOT NULL AND email = $2)',
      [phone_number, email || null]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this phone number or email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const userResult = await pool.query(
      `INSERT INTO users (phone_number, email, full_name, role, password_hash)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, phone_number, email, full_name, role`,
      [phone_number, email || null, full_name, role, passwordHash]
    );
    const user = userResult.rows[0];

    // If registering as a driver (or both) and vehicle details were provided, create the vehicle + session too
    if ((role === 'driver' || role === 'both') && vehicle && vehicle.make) {
      const vehicleResult = await pool.query(
        `INSERT INTO vehicles (driver_id, make, model, color, license_plate)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [user.id, vehicle.make, vehicle.model, vehicle.color, vehicle.license_plate]
      );
      await pool.query(
        `INSERT INTO driver_sessions (driver_id, vehicle_id, status) VALUES ($1, $2, 'offline')`,
        [user.id, vehicleResult.rows[0].id]
      );
    }

    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body; // identifier = phone number OR email

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Phone number/email and password are required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, phone_number, email, full_name, role, password_hash FROM users WHERE phone_number = $1 OR email = $1',
      [identifier]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid phone number/email or password' });
    }

    const user = result.rows[0];

    if (!user.password_hash) {
      return res.status(401).json({ error: 'This account has no password set. Try "Forgot password" or sign in with Google.' });
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid phone number/email or password' });
    }

    delete user.password_hash;
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/change-password', async (req, res) => {
  const { user_id, current_password, new_password } = req.body;

  if (!user_id || !current_password || !new_password) {
    return res.status(400).json({ error: 'user_id, current_password, and new_password are required' });
  }
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }

  try {
    const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [user_id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const matches = await bcrypt.compare(current_password, result.rows[0].password_hash || '');
    if (!matches) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const newHash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user_id]);

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// NOTE: this is a simplified "forgot password" flow with no OTP/email verification step —
// anyone who knows the phone number or email can reset the password. Fine for a personal
// test project, but not secure enough for a real public app (would need a verification
// code sent via SMS or email before allowing the reset).
app.post('/api/auth/forgot-password', async (req, res) => {
  const { identifier, new_password } = req.body;

  if (!identifier || !new_password) {
    return res.status(400).json({ error: 'identifier (phone or email) and new_password are required' });
  }
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }

  try {
    const result = await pool.query('SELECT id FROM users WHERE phone_number = $1 OR email = $1', [identifier]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No account found with that phone number or email' });
    }

    const newHash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, result.rows[0].id]);

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/google', async (req, res) => {
  const { email, full_name, google_id, role } = req.body;
  // NOTE: In this simplified version, the frontend verifies the Google token client-side
  // via Google Identity Services and sends us the decoded profile. For production use,
  // verify the ID token server-side with google-auth-library instead of trusting the client.

  if (!email || !google_id) {
    return res.status(400).json({ error: 'email and google_id are required' });
  }

  try {
    let result = await pool.query('SELECT id, phone_number, email, full_name, role FROM users WHERE google_id = $1 OR email = $2', [google_id, email]);

    if (result.rows.length > 0) {
      // Existing user — make sure google_id is linked
      await pool.query('UPDATE users SET google_id = $1 WHERE id = $2', [google_id, result.rows[0].id]);
      return res.json({ user: result.rows[0] });
    }

    // New user — create a minimal account. Phone number is required by the schema,
    // so we use a placeholder the user can update later; role defaults to rider.
    const placeholderPhone = `google_${google_id}`;
    const insertResult = await pool.query(
      `INSERT INTO users (phone_number, email, full_name, role, google_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, phone_number, email, full_name, role`,
      [placeholderPhone, email, full_name || email, role || 'rider', google_id]
    );

    res.json({ user: insertResult.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/drivers', async (req, res) => {
  const { lat, lng, radius_km } = req.query;

  try {
    let query, params;

    if (lat && lng && radius_km) {
      // Haversine formula in a subquery, filtered with WHERE on the outer query
      query = `
        SELECT * FROM (
          SELECT ds.id, ds.driver_id, ds.current_lat, ds.current_lng, u.full_name, v.make, v.model, v.color, v.license_plate,
            (6371 * acos(
              cos(radians($1)) * cos(radians(ds.current_lat)) *
              cos(radians(ds.current_lng) - radians($2)) +
              sin(radians($1)) * sin(radians(ds.current_lat))
            )) AS distance_km
          FROM driver_sessions ds
          JOIN users u ON ds.driver_id = u.id
          JOIN vehicles v ON ds.vehicle_id = v.id
          WHERE ds.status = 'online'
        ) sub
        WHERE distance_km <= $3
        ORDER BY distance_km ASC
      `;
      params = [lat, lng, radius_km];
    } else {
      // fallback: return all online drivers, no filtering
      query = `
        SELECT ds.id, ds.driver_id, ds.current_lat, ds.current_lng, u.full_name, v.make, v.model, v.color, v.license_plate
        FROM driver_sessions ds
        JOIN users u ON ds.driver_id = u.id
        JOIN vehicles v ON ds.vehicle_id = v.id
        WHERE ds.status = 'online'
      `;
      params = [];
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/drivers/:driver_id', async (req, res) => {
  const { driver_id } = req.params;
  try {
    const result = await pool.query(
      `SELECT ds.id, ds.driver_id, ds.current_lat, ds.current_lng, u.full_name, v.make, v.model, v.color, v.license_plate
       FROM driver_sessions ds
       JOIN users u ON ds.driver_id = u.id
       JOIN vehicles v ON ds.vehicle_id = v.id
       WHERE ds.driver_id = $1`,
      [driver_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Driver not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ride-requests', async (req, res) => {
  const { pickup_lat, pickup_lng, destination_lat, destination_lng, rider_id } = req.body;

  if (!rider_id) {
    return res.status(400).json({ error: 'rider_id is required — please log in' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO ride_requests (rider_id, pickup_lat, pickup_lng, destination_lat, destination_lng, status)
       VALUES ($1, $2, $3, $4, $5, 'searching')
       RETURNING *`,
      [rider_id, pickup_lat, pickup_lng, destination_lat, destination_lng]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/ride-requests/latest', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM ride_requests WHERE status = 'searching' ORDER BY created_at DESC LIMIT 1`
    );
    if (result.rows.length === 0) {
      return res.json(null);
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/ride-requests/pending', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT rr.*, u.full_name AS rider_name, u.phone_number AS rider_phone
       FROM ride_requests rr
       JOIN users u ON u.id = rr.rider_id
       WHERE rr.status = 'searching'
       ORDER BY rr.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ride-requests/:id/accept', async (req, res) => {
  const { id } = req.params;
  const { driver_id } = req.body;

  try {
    const result = await pool.query(
      `UPDATE ride_requests SET status = 'accepted', driver_id = $1 WHERE id = $2 AND status = 'searching' RETURNING *`,
      [driver_id, id]
    );

    if (result.rows.length === 0) {
      return res.status(409).json({ error: 'Ride request no longer available' });
    }

    const rideRequest = result.rows[0];

    // Fetch driver + vehicle details to send along with the notification
    const driverInfo = await pool.query(
      `SELECT u.full_name, v.make, v.model, v.color, v.license_plate
       FROM users u JOIN vehicles v ON v.driver_id = u.id
       WHERE u.id = $1`,
      [driver_id]
    );

    io.emit('ride:accepted', {
      ride_request: rideRequest,
      driver: driverInfo.rows[0] || null
    });

    res.json(rideRequest);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/ride-requests/:id/status', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // expected: 'picked_up' or 'completed'

  try {
    const result = await pool.query(
      `UPDATE ride_requests SET status = $1 WHERE id = $2 RETURNING *`,
      [status, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Ride request not found' });
    }

    io.emit('ride:statusUpdate', { id: parseInt(id), status });

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/driver-sessions/:driver_id/status', async (req, res) => {
  const { driver_id } = req.params;
  const { status } = req.body; // expected: 'online' or 'offline'

  if (!['online', 'offline'].includes(status)) {
    return res.status(400).json({ error: 'status must be online or offline' });
  }

  try {
    const result = await pool.query(
      `UPDATE driver_sessions SET status = $1, last_updated_at = NOW() WHERE driver_id = $2 RETURNING *`,
      [status, driver_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No driver session found for this driver' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ride-requests/:id/rating', async (req, res) => {
  const { id } = req.params;
  const { rating, comment } = req.body;

  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'rating must be between 1 and 5' });
  }

  try {
    const rideResult = await pool.query(
      `UPDATE ride_requests SET rating = $1, rating_comment = $2 WHERE id = $3 AND status = 'completed' RETURNING *`,
      [rating, comment || null, id]
    );

    if (rideResult.rows.length === 0) {
      return res.status(404).json({ error: 'Completed ride request not found' });
    }

    const driverId = rideResult.rows[0].driver_id;

    if (driverId) {
      const avgResult = await pool.query(
        `SELECT AVG(rating)::numeric(2,1) AS avg_rating FROM ride_requests WHERE driver_id = $1 AND rating IS NOT NULL`,
        [driverId]
      );
      await pool.query(`UPDATE users SET rating_avg = $1 WHERE id = $2`, [avgResult.rows[0].avg_rating, driverId]);
    }

    res.json(rideResult.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/ride-requests/:id/cancel', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `UPDATE ride_requests SET status = 'cancelled' WHERE id = $1 RETURNING *`,
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Ride request not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  // A driver's app sends their location periodically
  socket.on('driver:location', async (data) => {
    const { driver_id, lat, lng } = data;

    try {
      await pool.query(
        `UPDATE driver_sessions SET current_lat = $1, current_lng = $2, last_updated_at = NOW() WHERE driver_id = $3`,
        [lat, lng, driver_id]
      );

      // Broadcast the new location to everyone watching the map
      io.emit('driver:locationUpdate', { driver_id, lat, lng });
    } catch (err) {
      console.error('Error updating driver location:', err);
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

const PORT = 3001;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
