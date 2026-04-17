// backend/routes/post.routes.js
const express = require('express');
const pool = require('../config/db');
const { protect } = require('../middleware/auth.middleware');
const { memberOrAdmin } = require('../middleware/role.middleware');
const upload = require('../middleware/upload');
const router = express.Router();

// GET /api/posts - Public: all published posts
router.get('/', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.name AS author_name, u.profile_pic AS author_pic 
       FROM posts p 
       JOIN users u ON p.author_id = u.id 
       WHERE p.status = 'published' 
       ORDER BY p.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/posts/:id - Public: single post
router.get('/:id', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.name AS author_name, u.profile_pic AS author_pic 
       FROM posts p 
       JOIN users u ON p.author_id = u.id 
       WHERE p.id = $1 AND p.status != 'removed'`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/posts - Member or Admin
router.post('/', protect, memberOrAdmin, upload.single('image'), async (req, res) => {
  try {
    const { title, body } = req.body;
    const image = req.file ? req.file.filename : '';

    const result = await pool.query(
      `INSERT INTO posts (title, body, image, author_id) 
       VALUES ($1, $2, $3, $4) 
       RETURNING *`,
      [title, body, image, req.user.id]
    );

    const post = result.rows[0];
    res.status(201).json(post);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT /api/posts/:id - Edit: owner or admin
router.put('/:id', protect, memberOrAdmin, upload.single('image'), async (req, res) => {
  try {
    const post = await pool.query('SELECT * FROM posts WHERE id = $1', [req.params.id]);

    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const isOwner = post.rows[0].author_id === req.user.id;
    const isAdmin = req.user.role === 'admin';

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    const { title, body } = req.body;
    const image = req.file ? req.file.filename : post.rows[0].image;

    const result = await pool.query(
      `UPDATE posts 
       SET title = $1, body = $2, image = $3, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $4 
       RETURNING *`,
      [title || post.rows[0].title, body || post.rows[0].body, image, req.params.id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE /api/posts/:id - Delete: owner or admin
router.delete('/:id', protect, memberOrAdmin, async (req, res) => {
  try {
    const post = await pool.query('SELECT * FROM posts WHERE id = $1', [req.params.id]);

    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const isOwner = post.rows[0].author_id === req.user.id;
    const isAdmin = req.user.role === 'admin';

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    await pool.query('DELETE FROM posts WHERE id = $1', [req.params.id]);
    res.json({ message: 'Post deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;