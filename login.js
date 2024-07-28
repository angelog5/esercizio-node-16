app.post("/users/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ msg: "Invalid username or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid username or password" });
    }

    const payload = { id: user.id, username: user.username };

    const token = jwt.sign(payload, process.env.SECRET_KEY, {
      expiresIn: "1h",
    });

    await pool.query("UPDATE users SET token = $1 WHERE id = $2", [
      token,
      user.id,
    ]);

    res.json({ token, id: user.id, username: user.username });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});
