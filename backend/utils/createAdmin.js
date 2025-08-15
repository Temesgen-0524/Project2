/** @format */

const User = require("../models/User");

const createDefaultAdmin = async () => {
	try {
		// Check if admin already exists
		const adminExists = await User.findOne({
			email: process.env.ADMIN_EMAIL || "admin@dbu.edu.et",
		});

		if (!adminExists) {
			const admin = await User.create({
				name: "System Administrator",
				email: process.env.ADMIN_EMAIL || "admin@dbu.edu.et",
				password: process.env.ADMIN_PASSWORD || "admin123",
				role: "admin",
				isAdmin: true,
				studentId: "ADMIN-001",
				department: "Administration",
				year: "Staff",
			});

			console.log("Default admin user created:", admin.email);
		}

		// Create other admin users based on your frontend admin credentials
		const adminUsers = [
			{
				name: "Alemnesh Tadesse",
				email: "president@dbu.edu.et",
				password: "admin123",
				role: "president",
				isAdmin: true,
				studentId: "PRES-001",
				department: "Student Affairs",
				year: "Staff",
			},
			{
				name: "Bekele Mekonnen",
				email: "studentdin@dbu.edu.et",
				password: "admin123",
				role: "student_din",
				isAdmin: true,
				studentId: "SDIN-001",
				department: "Student Affairs",
				year: "Staff",
			},
			{
				name: "Hewan Tadesse",
				email: "academic@dbu.edu.et",
				password: "admin123",
				role: "academic_affairs",
				isAdmin: true,
				studentId: "ACAD-001",
				department: "Academic Affairs",
				year: "Staff",
			},
			{
				name: "Dawit Mekonnen",
				email: "clubs@dbu.edu.et",
				password: "admin123",
				role: "clubs_associations",
				isAdmin: true,
				studentId: "CLUB-001",
				department: "Student Activities",
				year: "Staff",
			},
			{
				name: "Sara Ahmed",
				email: "dining@dbu.edu.et",
				password: "admin123",
				role: "dining_services",
				isAdmin: true,
				studentId: "DINE-001",
				department: "Dining Services",
				year: "Staff",
			},
			{
				name: "Michael Tesfaye",
				email: "sports@dbu.edu.et",
				password: "admin123",
				role: "sports_culture",
				isAdmin: true,
				studentId: "SPRT-001",
				department: "Sports & Culture",
				year: "Staff",
			},
		];

		for (const adminData of adminUsers) {
			const existingAdmin = await User.findOne({ email: adminData.email });
			if (!existingAdmin) {
				await User.create(adminData);
				console.log(`Admin user created: ${adminData.email}`);
			}
		}

		// Create some sample students for testing
		const sampleStudents = [
			{
				name: "John Doe",
				email: "student@dbu.edu.et",
				password: "student123",
				role: "student",
				isAdmin: false,
				studentId: "DBU-2024-001",
				department: "Computer Science",
				year: "4th Year",
			},
			{
				name: "Jane Smith",
				email: "jane.smith@dbu.edu.et",
				password: "student123",
				role: "student",
				isAdmin: false,
				studentId: "DBU-2024-002",
				department: "Engineering",
				year: "3rd Year",
			},
		];

		for (const studentData of sampleStudents) {
			const existingStudent = await User.findOne({ email: studentData.email });
			if (!existingStudent) {
				await User.create(studentData);
				console.log(`Sample student created: ${studentData.email}`);
			}
		}
	} catch (error) {
		console.error("Error creating default users:", error);
	}
};

module.exports = { createDefaultAdmin };
