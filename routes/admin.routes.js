// backend/routes/admin.routes.js
const express = require('express');
const pool = require('../config/db');
const { protect } = require('../middleware/auth.middleware');
const { adminOnly } = require('../middleware/role.middleware');
const router = express.Router();

// All routes require admin role
router.use(protect, adminOnly);

// GET /api/admin/users - List all non-admin members
router.get('/users', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role, status, created_at 
       FROM users 
       WHERE role != 'admin' 
       ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT /api/admin/users/:id/status - Toggle member active/inactive
router.put('/users/:id/status', async (req, res) => {
  try {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);

    if (user.rows.length === 0 || user.rows[0].role === 'admin') {
      return res.status(404).json({ message: 'User not found' });
    }

    const newStatus = user.rows[0].status === 'active' ? 'inactive' : 'active';

    const result = await pool.query(
      `UPDATE users 
       SET status = $1, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $2 
       RETURNING id, name, email, role, status`,
      [newStatus, req.params.id]
    );

    res.json({ message: `User is now ${newStatus}`, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/admin/posts - List ALL posts
router.get('/posts', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.name AS author_name, u.email AS author_email 
       FROM posts p 
       JOIN users u ON p.author_id = u.id 
       ORDER BY p.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT /api/admin/posts/:id/remove - Mark post as removed
router.put('/posts/:id/remove', async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE posts 
       SET status = 'removed', updated_at = CURRENT_TIMESTAMP 
       WHERE id = $1 
       RETURNING *`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    res.json({ message: 'Post has been removed', post: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;