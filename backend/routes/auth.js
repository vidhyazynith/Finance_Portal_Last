import express from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import Employee from '../models/Employee.js'
import { authenticateToken, requireRole } from '../middleware/auth.js';
import { sendEmployeeCredentials } from '../services/emailService.js';

const router = express.Router();

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email, isActive: true });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        personId: user.personId,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Admin-only: Register employee with email notification
// router.post('/register/employee', authenticateToken, requireRole('admin'), async (req, res) => {
//   try {
//     const { 
//       personId, 
//       email, 
//       password,
//       name,
//       designation,
//       department,
//       phone,
//       address,
//       joiningDate
//     } = req.body;

//     // Validation
//     if (!personId || !email || !password || !name || !designation || !department || !phone || !address || !joiningDate) {
//       return res.status(400).json({ message: 'All fields are required' });
//     }

//     if (password.length < 6) {
//       return res.status(400).json({ message: 'Password must be at least 6 characters' });
//     }

//     // Check if user exists
//     const existingUser = await User.findOne({
//       $or: [{ email }, { personId }]
//     });

//     if (existingUser) {
//       return res.status(400).json({ message: 'User already exists with this email or Person ID' });
//     }

//     // Check if employee already exists
//     const existingEmployee = await Employee.findOne({
//       $or: [{ email }, { employeeId: personId }]
//     });

//     if (existingEmployee) {
//       return res.status(400).json({ message: 'Employee already exists with this email or Employee ID' });
//     }

//     // Create user
//     const user = new User({
//       personId,
//       email,
//       password,
//       role: 'employee',
//       createdBy: req.user._id
//     });

//     await user.save();

//     // Create employee record
//     const employee = new Employee({
//       employeeId: personId, // Link through personId
//       name,
//       email,
//       designation,
//       department,
//       phone,
//       address,
//       joiningDate: new Date(joiningDate)
//     });

//     await employee.save();

//     // Send email with credentials (don't await to avoid blocking response)
//     sendEmployeeCredentials(
//       { personId, email }, 
//       password
//     ).then(result => {
//       if (result.success) {
//         console.log(`Credentials email sent to ${email}`);
//       } else {
//         console.error(`Failed to send email to ${email}:`, result.error);
//       }
//     });

//     res.status(201).json({
//       message: 'Employee registered successfully. Credentials email sent.',
//       employee: {
//         id: employee._id,
//         personId: employee.personId,
//         email: employee.email,
//         role: employee.role,
//         createdAt: employee.createdAt
//       }
//     });
//   } catch (error) {
//     console.error('Error registering employee:', error);
//     res.status(500).json({ message: 'Server error during employee registration' });
//   }
// });

// Verify token
router.post('/verify', async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ valid: false, message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ valid: false, message: 'User not found' });
    }

    res.json({ valid: true, user });
  } catch (error) {
    res.status(401).json({ valid: false, message: 'Invalid token' });
  }
});

export default router;