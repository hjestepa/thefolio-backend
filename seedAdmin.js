// backend/seedAdmin.js
require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function seed() {
  try {
    // Check if admin already exists
    const exists = await pool.query("SELECT id FROM users WHERE email = 'admin@animeverse.com'");

    if (exists.rows.length > 0) {
      console.log('Admin already exists.');
      process.exit();
    }

    // Hash password manually (no Mongoose pre-save hook)
    const hashed = await bcrypt.hash('Admin123!', 12);

    await pool.query(
      `INSERT INTO users (name, email, password, role) 
       VALUES ($1, $2, $3, $4)`,
      ['AnimeVerse Admin', 'admin@animeverse.com', hashed, 'admin']
    );

    console.log('✅ Admin created successfully!');
    console.log('📧 Email: admin@animeverse.com');
    console.log('🔑 Password: Admin123!');
    process.exit();
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

seed();