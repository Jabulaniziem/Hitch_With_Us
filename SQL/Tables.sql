CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  phone_number VARCHAR(20) UNIQUE NOT NULL,
  full_name VARCHAR(100),
  role VARCHAR(10) CHECK (role IN ('rider', 'driver', 'both')),
  rating_avg DECIMAL(2,1) DEFAULT 5.0,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE vehicles (
  id SERIAL PRIMARY KEY,
  driver_id INTEGER REFERENCES users(id),
  make VARCHAR(50),
  model VARCHAR(50),
  color VARCHAR(30),
  license_plate VARCHAR(20),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE driver_sessions (
  id SERIAL PRIMARY KEY,
  driver_id INTEGER REFERENCES users(id),
  vehicle_id INTEGER REFERENCES vehicles(id),
  status VARCHAR(10) DEFAULT 'offline',
  current_lat DECIMAL(9,6),
  current_lng DECIMAL(9,6),
  last_updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE ride_requests (
  id SERIAL PRIMARY KEY,
  rider_id INTEGER REFERENCES users(id),
  pickup_lat DECIMAL(9,6),
  pickup_lng DECIMAL(9,6),
  destination_lat DECIMAL(9,6),
  destination_lng DECIMAL(9,6),
  status VARCHAR(15) DEFAULT 'searching',
  created_at TIMESTAMP DEFAULT NOW()
);
