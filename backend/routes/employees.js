import express from 'express';
import { registerEmployee,
  getAllEmployee,
  getEmployeeById,
  updateEmployee,
  deleteEmployee,
 } from '../Controllers/employeeController.js';
import { authenticateToken, requireRole } from '../middleware/auth.js';
 
const router = express.Router();
 
 
router.post('/register/employee', authenticateToken, requireRole('admin'),registerEmployee);
 
// Get all employees
router.get('/', authenticateToken, requireRole('admin'), getAllEmployee);
 
// Get employee by ID
router.get('/:id', authenticateToken, getEmployeeById);
 
// Update employee
router.put('/:id', authenticateToken, requireRole('admin'), updateEmployee );
 
// Delete employee
router.delete('/:id', authenticateToken, requireRole('admin'), deleteEmployee);
 
export default router;