import Employee from "../models/Employee.js";
import User from '../models/User.js';
import { sendEmployeeCredentials } from '../services/emailService.js';
import { parsePhoneNumberFromString } from 'libphonenumber-js';
import bcrypt from "bcryptjs";
 
// Register employee
export const registerEmployee = async (req, res) => {
  try {
    const {
      personId,
      email,
      password,
      name,
      designation,
      department,
      phone,
      countryCode,
      address,
      panNumber, // Added PAN number
      joiningDate,
      status
    } = req.body;
 
    // Validation
    if (!personId || !email || !password || !name || !designation || !department || !phone || !address || !panNumber || !joiningDate) {
      return res.status(400).json({ message: 'All fields are required' });
    }
 
    const phoneNumber = parsePhoneNumberFromString(`${countryCode}${phone}`);
    if (!phoneNumber || !phoneNumber.isValid()) {
      return res.status(400).json({ message: 'Invalid phone number format for the selected country' });
    }
 
    console.log('nmberrrrrrrrrrrrrr');
    // ✅ Standardize phone format
    const formattedPhone = phoneNumber.number; // e.g. +919876543210
 
    console.log('12345678uytrefgh');
 
    // Validate PAN number format
    const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
    if (!panRegex.test(panNumber.toUpperCase())) {
      return res.status(400).json({ message: 'Please enter a valid PAN number (e.g., ABCDE1234F)' });
    }
 
    // Password validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,14}$/;
 
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        message:
          'Password must be 8-14 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.'
      });
    }
 
 
    // Validate employee ID format
    if (!personId.startsWith('ZIC') || personId.length !== 6) {
      return res.status(400).json({ message: 'Invalid employee ID format. Must be ZIC followed by 3 digits (e.g., ZIC001)' });
    }
 
    // Check if the numeric part is valid
    const numericPart = personId.replace('ZIC', '');
    if (!/^\d{3}$/.test(numericPart)) {
      return res.status(400).json({ message: 'Invalid employee ID format. Must be ZIC followed by 3 digits (e.g., ZIC001)' });
    }
 
    // Check if user exists
    const existingUser = await User.findOne({
      $or: [{ email }, { personId }]
    });
 
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email or Person ID' });
    }
 
    // Check if employee already exists
    const existingEmployee = await Employee.findOne({
      $or: [
        { email },
        { employeeId: personId },
        { panNumber: panNumber.toUpperCase() } // Check for duplicate PAN
      ]
    });
 
    if (existingEmployee) {
      if (existingEmployee.email === email) {
        return res.status(400).json({ message: 'Employee already exists with this email' });
      }
      if (existingEmployee.employeeId === personId) {
        return res.status(400).json({ message: 'Employee already exists with this Employee ID' });
      }
      if (existingEmployee.panNumber === panNumber.toUpperCase()) {
        return res.status(400).json({ message: 'Employee already exists with this PAN number' });
      }
    }
 
     const hashedPassword = await bcrypt.hash(password, 10);
 
    // ✅ Create user
    const user = new User({
      personId,
      email,
      password: hashedPassword,
      role: "employee",
      createdBy: req.user._id,
    });
 
   
 
    // Create employee record
    const employee = new Employee({
      employeeId: personId,
      name,
      email,
      designation,
      department,
      phone: formattedPhone,
      address,
      panNumber: panNumber.toUpperCase(), // Store as uppercase
      joiningDate: new Date(joiningDate),
      status: status || 'Active'
    });
        console.log('12345678uytrefgh');
 
    await employee.save();
        console.log('12345678uytrefgh');
 
    // Send email with credentials
    sendEmployeeCredentials(
      { personId, email },
      password
    ).then(result => {
      if (result.success) {
        console.log(`Credentials email sent to ${email}`);
      } else {
        console.error(`Failed to send email to ${email}:`, result.error);
      }
    });
 
    res.status(201).json({
      message: 'Employee registered successfully. Credentials email sent.',
      employee: {
        id: employee._id,
        employeeId: employee.employeeId,
        name: employee.name,
        email: employee.email,
        designation: employee.designation,
        department: employee.department,
        phone: employee.phone,
        address: employee.address,
        panNumber: employee.panNumber,
        joiningDate: employee.joiningDate,
        status: employee.status,
        createdAt: employee.createdAt
      }
    });
  } catch (error) {
    console.error('Error registering employee:', error);
   
    // Handle duplicate key errors
    if (error.code === 11000) {
      if (error.keyPattern && error.keyPattern.panNumber) {
        return res.status(400).json({
          message: 'PAN number already exists. Please use a different PAN number.'
        });
      }
      if (error.keyPattern && error.keyPattern.employeeId) {
        return res.status(400).json({
          message: 'Employee ID already exists. Please try again.'
        });
      }
      if (error.keyPattern && error.keyPattern.email) {
        return res.status(400).json({
          message: 'Email already exists. Please use a different email.'
        });
      }
    }
   
    res.status(500).json({ message: 'Server error during employee registration' });
  }
};
 
// Get all employees
export const getAllEmployee = async (req, res) => {
  try {
    const employees = await Employee.find().sort({ createdAt: -1 });
   
    console.log('Employees with status:');
   
    res.json({ employees });
  } catch (error) {
    res.status(500).json({ message: 'Server error while fetching employees' });
  }
};
 
// Get employee by ID
export const getEmployeeById = async (req, res) => {
  try {
    const employee = await Employee.findOne({ employeeId: req.params.id });
    if (!employee) {
      return res.status(404).json({ message: 'Employee not found' });
    }
    res.json({ employee });
  } catch (error) {
    res.status(500).json({ message: 'Server error while fetching employee' });
  }
};
 
// Update employee
export const updateEmployee = async (req, res) => {
  try {
    const { panNumber, status, phone, countryCode, ...otherFields } = req.body;
 
    const updateData = {
      ...otherFields,
      status: status || 'Active'
    };
 
    // Validate phone only if provided
    if (typeof phone !== 'undefined') {
      const phoneNumber = parsePhoneNumberFromString(`${countryCode}${phone}`);
      if (!phoneNumber || !phoneNumber.isValid()) {
        return res.status(400).json({ message: 'Invalid phone number format for the selected country' });
      }
      updateData.phone = phoneNumber.number;
    }
 
    // Validate PAN if provided
    if (panNumber) {
      const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
      if (!panRegex.test(panNumber.toUpperCase())) {
        return res.status(400).json({ message: 'Please enter a valid PAN number (e.g., ABCDE1234F)' });
      }
 
      // Check for existing PAN in another employee
      const existingEmployeeWithPan = await Employee.findOne({
        panNumber: panNumber.toUpperCase(),
        employeeId: { $ne: req.params.id }
      });
 
      if (existingEmployeeWithPan) {
        return res.status(400).json({ message: 'PAN number already exists for another employee' });
      }
 
      updateData.panNumber = panNumber.toUpperCase();
    }
 
    const employee = await Employee.findOneAndUpdate(
      { employeeId: req.params.id },
      updateData,
      { new: true, runValidators: true }
    );
 
    if (!employee) {
      return res.status(404).json({ message: 'Employee not found' });
    }
 
    res.json({
      message: 'Employee updated successfully',
      employee: {
        id: employee._id,
        employeeId: employee.employeeId,
        name: employee.name,
        email: employee.email,
        designation: employee.designation,
        department: employee.department,
        phone: employee.phone,
        address: employee.address,
        panNumber: employee.panNumber,
        joiningDate: employee.joiningDate,
        status: employee.status
      }
    });
  } catch (error) {
    console.error('Error updating employee:', error);
 
    if (error.code === 11000) {
      if (error.keyPattern && error.keyPattern.panNumber) {
        return res.status(400).json({
          message: 'PAN number already exists. Please use a different PAN number.'
        });
      }
    }
 
    res.status(500).json({ message: 'Server error while updating employee' });
  }
};
 
 
// Delete employee
export const deleteEmployee = async (req, res) => {
  try {
    const employee = await Employee.findOneAndDelete({ employeeId: req.params.id });
    if (!employee) {
      return res.status(404).json({ message: 'Employee not found' });
    }
   
    // Also delete the associated user
    await User.findOneAndDelete({ personId: req.params.id });
   
    res.json({ message: 'Employee deleted successfully' });
  } catch (error) {
    console.error('Error deleting employee:', error);
    res.status(500).json({ message: 'Server error while deleting employee' });
  }
};
 
// Get employees by status
export const getEmployeesByStatus = async (req, res) => {
  try {
    const { status } = req.params;
   
    if (!['Active', 'Inactive'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status. Use "Active" or "Inactive".' });
    }
   
    const employees = await Employee.find({ status }).sort({ createdAt: -1 });
   
    res.json({
      employees: employees.map(emp => ({
        id: emp._id,
        employeeId: emp.employeeId,
        name: emp.name,
        email: emp.email,
        designation: emp.designation,
        department: emp.department,
        phone: emp.phone,
        address: emp.address,
        panNumber: emp.panNumber,
        joiningDate: emp.joiningDate,
        status: emp.status
      }))
    });
  } catch (error) {
    console.error('Error fetching employees by status:', error);
    res.status(500).json({ message: 'Server error while fetching employees by status' });
  }
};
 
// Search employees
export const searchEmployees = async (req, res) => {
  try {
    const { query } = req.query;
   
    if (!query || query.trim() === '') {
      return res.status(400).json({ message: 'Search query is required' });
    }
   
    const searchRegex = new RegExp(query, 'i');
   
    const employees = await Employee.find({
      $or: [
        { employeeId: searchRegex },
        { name: searchRegex },
        { email: searchRegex },
        { designation: searchRegex },
        { department: searchRegex },
        { panNumber: searchRegex } // Include PAN number in search
      ]
    }).sort({ createdAt: -1 });
   
    res.json({
      employees: employees.map(emp => ({
        id: emp._id,
        employeeId: emp.employeeId,
        name: emp.name,
        email: emp.email,
        designation: emp.designation,
        department: emp.department,
        phone: emp.phone,
        address: emp.address,
        panNumber: emp.panNumber,
        joiningDate: emp.joiningDate,
        status: emp.status
      }))
    });
  } catch (error) {
    console.error('Error searching employees:', error);
    res.status(500).json({ message: 'Server error while searching employees' });
  }
};
 