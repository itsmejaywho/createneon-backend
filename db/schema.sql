CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'user',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS neon_design_orders (
  id SERIAL PRIMARY KEY,
  step_1_text TEXT NOT NULL,
  step_1_alignment VARCHAR(20) NOT NULL,
  step_1_font_id VARCHAR(100) NOT NULL,
  step_1_font_name VARCHAR(100) NOT NULL,
  step_2_color_id VARCHAR(100) NOT NULL,
  step_2_color_name VARCHAR(100) NOT NULL,
  step_3_width_cm INTEGER NOT NULL,
  step_3_height_cm INTEGER NOT NULL,
  step_4_location_id VARCHAR(50) NOT NULL,
  step_4_location_label VARCHAR(100) NOT NULL,
  quoted_price INTEGER NOT NULL,
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
