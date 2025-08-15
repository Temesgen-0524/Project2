/** @format */

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
	{
		name: {
			type: String,
			required: [true, "Please provide a name"],
			trim: true,
			maxlength: [50, "Name cannot be more than 50 characters"],
		},
		email: {
			type: String,
			required: [true, "Please provide an email"],
			unique: true,
			lowercase: true,
			match: [
				/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
				"Please provide a valid email",
			],
		},
		password: {
			type: String,
			required: [true, "Please provide a password"],
			minlength: [6, "Password must be at least 6 characters"],
			select: false,
		},
		studentId: {
			type: String,
			sparse: true,
			unique: true,
		},
		department: {
			type: String,
			trim: true,
		},
		year: {
			type: String,
			enum: [
				"1st Year",
				"2nd Year",
				"3rd Year",
				"4th Year",
				"5th Year",
				"Graduate",
				"Staff",
			],
		},
		role: {
			type: String,
			enum: [
				"student",
				"admin",
				"president",
				"student_din",
				"vice_president",
				"secretary",
				"speaker",
				"academic_affairs",
				"general_service",
				"dining_services",
				"sports_culture",
				"clubs_associations",
			],
			default: "student",
		},
		isAdmin: {
			type: Boolean,
			default: false,
		},
		isActive: {
			type: Boolean,
			default: true,
		},
		profileImage: {
			type: String,
			default: null,
		},
		phoneNumber: {
			type: String,
			trim: true,
		},
		address: {
			type: String,
			trim: true,
		},
		joinedClubs: [
			{
				type: mongoose.Schema.Types.ObjectId,
				ref: "Club",
			},
		],
		votedElections: [
			{
				type: mongoose.Schema.Types.ObjectId,
				ref: "Election",
			},
		],
		lastLogin: {
			type: Date,
			default: Date.now,
		},
	},
	{
		timestamps: true,
	}
);

// Index for better query performance
userSchema.index({ email: 1 });
userSchema.index({ studentId: 1 });
userSchema.index({ role: 1 });

// Encrypt password before saving
userSchema.pre("save", async function (next) {
	if (!this.isModified("password")) {
		next();
	}

	const salt = await bcrypt.genSalt(10);
	this.password = await bcrypt.hash(this.password, salt);
});

// Match user entered password to hashed password in database
userSchema.methods.matchPassword = async function (enteredPassword) {
	return await bcrypt.compare(enteredPassword, this.password);
};

// Update last login
userSchema.methods.updateLastLogin = function () {
	this.lastLogin = new Date();
	return this.save();
};

module.exports = mongoose.model("User", userSchema);
