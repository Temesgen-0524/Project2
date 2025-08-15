/** @format */

// controllers/authController.js
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const generateToken = require("../utils/generateToken");

exports.login = async (req, res) => {
	const { email, password } = req.body;

	const user = await User.findOne({ email }).select("+password");
	if (!user) return res.status(401).json({ message: "Invalid credentials" });

	const ok = await bcrypt.compare(password, user.password);
	if (!ok) return res.status(401).json({ message: "Invalid credentials" });

	const token = generateToken(user._id);

	// Don’t send hashed password back
	const { password: _, ...safeUser } = user.toObject();

	res.json({ user: safeUser, token });
};
const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
	expiresIn: process.env.JWT_EXPIRES_IN || "30d",
});

res.json({
	success: true,
	token,
	user: {
		id: user._id,
		email: user.email,
		name: user.name,
		role: user.role,
	},
});
