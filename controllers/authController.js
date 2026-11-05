const bcrypt=require("bcrypt");

const User=require("../models/User");

const generateToken=require("../utils/jwt");

const createPlatformAuditLog =
require("../utils/platformAuditLogger");



exports.register = async (req, res) => {
    try {
        const {
            username,
            email,
            password,
            role = "VIEWER"
        } = req.body || {};

        if (
            typeof username !== "string" ||
            username.trim().length < 3 ||
            username.trim().length > 100
        ) {
            return res.status(400).json({
                message: "Username must contain 3 to 100 characters"
            });
        }

        if (
            typeof email !== "string" ||
            email.length > 254 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
        ) {
            return res.status(400).json({
                message: "Invalid email address"
            });
        }

        if (
            typeof password !== "string" ||
            password.length < 12 ||
            password.length > 72
        ) {
            return res.status(400).json({
                message: "Password must contain 12 to 72 characters"
            });
        }

        if (
            typeof role !== "string" ||
            !["ADMIN", "ANALYST", "VIEWER"].includes(role)
        ) {
            return res.status(400).json({
                message: "Invalid user role"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const existingUser = await User.findOne({
            where: { email: normalizedEmail }
        });

        if (existingUser) {
            return res.status(409).json({
                message: "Email already registered"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            username: username.trim(),
            email: normalizedEmail,
            password: hashedPassword,
            role
        });

        await createPlatformAuditLog({
            username: req.user.username,
            action: "USER_REGISTER",
            module: "AUTH",
            severity: "MEDIUM",
            ipAddress: req.ip,
            description:
                `Administrator created account ${user.username} with role ${role}`
        });

        return res.status(201).json({
            success: true,
            message: "User created successfully",
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("User registration failed:", error);

        if (error.name === "SequelizeUniqueConstraintError") {
            return res.status(409).json({
                message: "Email already registered"
            });
        }

        return res.status(500).json({
            message: "Unable to register user"
        });
    }
};


// Use identical client responses for unknown accounts and incorrect passwords.
// Login remains public, but account existence must not be disclosed.
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body || {};
        if (typeof email !== "string" || typeof password !== "string" ||
            email.length > 254 || !email.trim() || !password) {
            return res.status(400).json({ message: "Email and password required" });
        }

        const normalizedEmail = email.trim().toLowerCase();
        const user = await User.findOne({ where: { email: normalizedEmail } });
        const valid = user ? await bcrypt.compare(password, user.password) : false;

        if (!valid) {
            try {
                await createPlatformAuditLog({
                    username: user?.username || normalizedEmail,
                    action: "LOGIN_FAILED",
                    module: "AUTH",
                    severity: "MEDIUM",
                    ipAddress: req.ip,
                    description: "Login failed - invalid credentials"
                });
            } catch (auditError) {
                console.error("Login failure audit failed:", auditError);
            }
            return res.status(401).json({ message: "Invalid email or password" });
        }

        if (!user.emailVerifiedAt) {
            return res.status(403).json({
                message: "Please verify your email address before signing in.",
                code: "EMAIL_VERIFICATION_REQUIRED"
            });
        }

        const token = generateToken(user);
        try {
            await createPlatformAuditLog({
                username: user.username,
                action: "LOGIN_SUCCESS",
                module: "AUTH",
                severity: "LOW",
                ipAddress: req.ip,
                description: "User successfully logged into SIEM platform"
            });
        } catch (auditError) {
            console.error("Login success audit failed:", auditError);
        }

        return res.json({ message: "Login Successful", token });
    } catch (error) {
        console.error("Login failed:", error);
        return res.status(500).json({ message: "Unable to process login" });
    }
};
