import React, { useState, useEffect } from 'react';
import { employeeService } from '../../services/employee';
import { useAuth } from '../../context/AuthContext';
import './Employee.css';
import PhoneInput from 'react-phone-number-input';
import 'react-phone-number-input/style.css';
import { isValidPhoneNumber } from 'react-phone-number-input';

const EmployeeManagement = ({ onEmployeeUpdate }) => {
  const { user, logout } = useAuth();
  const [employees, setEmployees] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [editingEmployee, setEditingEmployee] = useState(null);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('active');
  const [isGeneratingId, setIsGeneratingId] = useState(false);
  const [formAttempts, setFormAttempts] = useState(0);
  const [phoneError, setPhoneError] = useState(''); // NEW: Separate state for phone validation

  const [formData, setFormData] = useState({
    personId: '',
    email: '',
    password: '',
    name: '',
    designation: '',
    department: '',
    phone: '',
    address: '',
    panNumber: '',
    joiningDate: '',
    status: 'Active'
  });

  // Skeleton data for loading state
  const skeletonEmployees = Array(5).fill().map((_, index) => ({
    _id: `skeleton-${index}`,
    employeeId: `ZIC${String(index + 1).padStart(3, '0')}`,
    name: '',
    email: '',
    designation: '',
    department: '',
    status: 'Active',
    isSkeleton: true
  }));

  // Designation options
  const designationOptions = [
    'Senior Developer',
    'Junior Developer',
    'Project Manager',
    'UI/UX Designer',
    'HR Manager',
    'Finance Analyst',
    'Sales Executive'
  ];

  // Department options
  const departmentOptions = [
    'Engineering',
    'Management',
    'Design',
    'Sales',
    'HR',
    'Finance',
    'Marketing',
    'Operations',
    'IT'
  ];

  // Load employees on component mount
  const loadEmployees = async () => {
    setLoading(true);
    try {
      const data = await employeeService.getEmployees();
      setEmployees(data.employees);
     
      if (onEmployeeUpdate) {
        onEmployeeUpdate();
      }
    } catch (error) {
      console.error('Error loading employees:', error);
      setError('Failed to load employees. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEmployees();
  }, []);

  // ID generation function
  const generateNextEmployeeId = async () => {
    try {
      const latestData = await employeeService.getEmployees();
      const existingEmployees = latestData.employees;
     
      const zicEmployeeIds = existingEmployees
        .map(emp => emp.employeeId)
        .filter(id => id && id.startsWith('ZIC'))
        .sort();

      if (zicEmployeeIds.length === 0) {
        return 'ZIC001';
      }

      const numbers = zicEmployeeIds.map(id => {
        const numStr = id.replace('ZIC', '');
        return parseInt(numStr, 10) || 0;
      });

      const maxNumber = Math.max(...numbers);

      for (let i = 1; i <= 5; i++) {
        const tryNumber = maxNumber + i;
        const tryId = `ZIC${tryNumber.toString().padStart(3, '0')}`;
       
        const exists = existingEmployees.some(emp => emp.employeeId === tryId);
        if (!exists) {
          return tryId;
        }
      }

      for (let i = 1; i <= 10; i++) {
        const tryNumber = maxNumber + 10 + i;
        const tryId = `ZIC${tryNumber.toString().padStart(3, '0')}`;
       
        const exists = existingEmployees.some(emp => emp.employeeId === tryId);
        if (!exists) {
          return tryId;
        }
      }

      throw new Error('Could not find available employee ID');
    } catch (error) {
      console.error('Error generating employee ID:', error);
      const timestamp = Date.now().toString().slice(-3);
      return `ZIC${timestamp}`;
    }
  };

  // Auto-dismiss messages
  useEffect(() => {
    if (success || error) {
      const timer = setTimeout(() => {
        setSuccess('');
        setError('');
      }, 5000);
     
      return () => clearTimeout(timer);
    }
  }, [success, error]);

  // NEW: Phone validation function
  const validatePhoneNumber = (phone) => {
    if (!phone) {
      setPhoneError('Phone number is required');
      return false;
    }
    
    if (!isValidPhoneNumber(phone)) {
      setPhoneError('Please enter a valid phone number for the selected country');
      return false;
    }
    
    setPhoneError('');
    return true;
  };

  // Handle update employee
  const handleUpdateEmployee = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    // Validate phone number
    if (!validatePhoneNumber(formData.phone)) {
      setLoading(false);
      return;
    }

    try {
      const updateData = { ...formData };

      // ✅ Remove password field if empty (don't overwrite password)
      if (!updateData.password) {
        delete updateData.password;
      }

      // ✅ Perform update
      await employeeService.updateEmployee(editingEmployee.employeeId, updateData);

      setSuccess('✅ Employee updated successfully!');
      setShowAddForm(false);
      setEditingEmployee(null);
      setPhoneError(''); // Clear phone error on success

      await loadEmployees();

      if (onEmployeeUpdate) {
        onEmployeeUpdate();
      }

    } catch (error) {
      console.error('Error updating employee:', error);
      setError(error.response?.data?.message || '❌ Failed to update employee. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Handle add button click
  const handleAddButtonClick = async () => {
    try {
      setIsGeneratingId(true);
      setError('');
      setPhoneError(''); // Clear phone error when opening form
      setFormAttempts(prev => prev + 1);

      await loadEmployees();
     
      const newId = await generateNextEmployeeId();

      setFormData({
        personId: newId,
        email: '',
        password: '',
        name: '',
        designation: '',
        department: '',
        phone: '',
        address: '',
        panNumber: '',
        joiningDate: '',
        status: 'Active'
      });

      setShowAddForm(true);
      setEditingEmployee(null);
     
    } catch (error) {
      console.error('Error opening add form:', error);
      setError('Failed to prepare employee form. Please try again.');
    } finally {
      setIsGeneratingId(false);
    }
  };

  // Handle status change with auto-tab switching
  const handleStatusChange = async (employeeId, currentStatus, newStatus) => {
    const confirmationMessage = `Are you sure you want to change the status from ${currentStatus} to ${newStatus}?`;
   
    if (window.confirm(confirmationMessage)) {
      try {
        await employeeService.updateEmployee(employeeId, { status: newStatus });
        await loadEmployees();
        if (onEmployeeUpdate) {
          onEmployeeUpdate();
        }
        setSuccess(`Employee status changed to ${newStatus} successfully!`);
       
        // Auto-switch tabs based on new status
        if (newStatus === 'Active') {
          setActiveTab('active');
        } else {
          setActiveTab('inactive');
        }
      } catch (error) {
        setError('Error updating employee status');
        console.error('Error updating employee status:', error);
      }
    }
  };

  // Handle add employee
  const handleAddEmployee = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    // Validate phone number
    if (!validatePhoneNumber(formData.phone)) {
      setLoading(false);
      return;
    }

    try {
      // ✅ Proceed with registration
      const response = await employeeService.registerEmployee(formData);

      setSuccess('✅ Employee registered successfully!');
      setShowAddForm(false);
      setEditingEmployee(null);
      setPhoneError(''); // Clear phone error on success

      // ✅ Reload employees list
      await loadEmployees();

      // ✅ Notify parent component (if applicable)
      if (onEmployeeUpdate) {
        onEmployeeUpdate();
      }

    } catch (error) {
      console.error('Registration error:', error);

      if (error.response?.data?.message?.includes('already exists')) {
        const newId = await generateNextEmployeeId();
        setFormData(prev => ({
          ...prev,
          personId: newId
        }));
        setError(`⚠️ Employee ID was taken. New ID generated: ${newId}. Please review and submit again.`);
      } else {
        setError(error.response?.data?.message || 'Registration failed. Please try again.');
      }

    } finally {
      setLoading(false);
    }
  };

  const handleEditEmployee = (employee) => {
    setEditingEmployee(employee);
    setFormData({
      personId: employee.employeeId,
      email: employee.email,
      password: '',
      name: employee.name,
      designation: employee.designation,
      department: employee.department,
      phone: employee.phone,
      address: employee.address,
      panNumber: employee.panNumber || '',
      joiningDate: employee.joiningDate ? employee.joiningDate.split('T')[0] : '',
      status: employee.status || 'Active'
    });
    setPhoneError(''); // Clear phone error when editing
    setShowAddForm(true);
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
   
    // Convert PAN number to uppercase as user types
    if (name === 'panNumber') {
      setFormData({
        ...formData,
        [name]: value.toUpperCase()
      });
    } else {
      setFormData({
        ...formData,
        [name]: value
      });
    }
  };

  const handlePhoneChange = (value) => {
    setFormData({
      ...formData,
      phone: value
    });
    
    // Real-time phone validation
    if (value) {
      if (!isValidPhoneNumber(value)) {
        setPhoneError('Please enter a valid phone number for the selected country');
      } else {
        setPhoneError('');
      }
    } else {
      setPhoneError('Phone number is required');
    }
  };

  const handleCloseModal = () => {
    setShowAddForm(false);
    setEditingEmployee(null);
    setError('');
    setPhoneError(''); // Clear phone error when closing modal
    setFormAttempts(0);
  };

  // Function to sort employees by Employee ID
  const sortEmployeesById = (employeesArray) => {
    return [...employeesArray].sort((a, b) => {
      const idA = a.employeeId?.replace(/\D/g, '') || '';
      const idB = b.employeeId?.replace(/\D/g, '') || '';
      const numA = parseInt(idA, 10) || 0;
      const numB = parseInt(idB, 10) || 0;
      return numA - numB;
    });
  };

  // Filter employees based on search term
  const filteredEmployees = employees.filter(employee =>
    employee.employeeId?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    employee.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    employee.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    employee.department?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    employee.panNumber?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Filter employees based on active tab
  const statusFilteredEmployees = filteredEmployees.filter(employee =>
    activeTab === 'active' ? employee.status === 'Active' : employee.status === 'Inactive'
  );

  // Sort the filtered employees by Employee ID
  const sortedEmployees = sortEmployeesById(statusFilteredEmployees);

  // Validate PAN number format
  const validatePanNumber = (pan) => {
    const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
    return panRegex.test(pan);
  };

  return (
    <div className="employee-management">
      {/* Success and Error Messages */}
      {success && (
        <div className="alert success-alert">
          <span>{success}</span>
          <button className="close-alert" onClick={() => setSuccess('')}>×</button>
        </div>
      )}

      {error && (
        <div className="alert error-alert">
          <span>{error}</span>
          <button className="close-alert" onClick={() => setError('')}>×</button>
        </div>
      )}

      {/* Header Section */}
      <div className="employee-header">
        <div className="header-left">
          <div className="search-box">
            {loading ? (
              <div className="skeleton skeleton-search"></div>
            ) : (
              <input
                type="text"
                placeholder="Search employees by ID, name, email, department, or PAN..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="search-input"
              />
            )}
          </div>
        </div>
       
        <div className="header-right">
          {!loading && (
            <button
              className="add-employee-btn"
              onClick={handleAddButtonClick}
              disabled={isGeneratingId}
            >
              <span className="btn-icon">+</span>
              {isGeneratingId ? 'Generating ID...' : 'Add Employee'}
            </button>
          )}
        </div>
      </div>

      {/* Control Tabs Section - Embedded in table card */}
      <div className="employees-table-container">
        {/* Tab Navigation - Embedded in table card */}
        <div className="table-card-header">
          <div className="tab-navigation">
            <button
              className={`tab-button ${activeTab === 'active' ? 'active' : ''}`}
              onClick={() => setActiveTab('active')}
            >
              Active Employees
            </button>
            <button
              className={`tab-button ${activeTab === 'inactive' ? 'active' : ''}`}
              onClick={() => setActiveTab('inactive')}
            >
              Inactive Employees
            </button>
          </div>
        </div>
        
        <table className="employees-table">
          <thead>
            <tr>
              <th>Employee ID</th>
              <th>Name</th>
              <th>Designation</th>
              <th>Department</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              // Skeleton loading state
              skeletonEmployees.map((employee, index) => (
                <tr key={employee._id} className="employee-row">
                  <td>
                    <div className="skeleton skeleton-text skeleton-text-small"></div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <div className="skeleton skeleton-text skeleton-text-medium"></div>
                      <div className="skeleton skeleton-text skeleton-text-large"></div>
                    </div>
                  </td>
                  <td>
                    <div className="skeleton skeleton-text skeleton-text-medium"></div>
                  </td>
                  <td>
                    <div className="skeleton skeleton-badge"></div>
                  </td>
                  <td>
                    <div className="skeleton skeleton-badge"></div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <div className="skeleton" style={{ width: '32px', height: '32px', borderRadius: '6px' }}></div>
                      <div className="skeleton" style={{ width: '32px', height: '32px', borderRadius: '6px' }}></div>
                    </div>
                  </td>
                </tr>
              ))
            ) : sortedEmployees.length === 0 ? (
              <tr>
                <td colSpan="6" className="empty-cell">
                  <div style={{ textAlign: 'center', padding: '40px', color: '#64748b' }}>
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                      <circle cx="12" cy="7" r="4"></circle>
                    </svg>
                    <p style={{ marginTop: '16px', fontSize: '16px', fontWeight: '600' }}>
                      No {activeTab === 'active' ? 'active' : 'inactive'} employees found
                    </p>
                    <p style={{ marginTop: '8px', fontSize: '14px' }}>
                      {searchTerm ? 'Try adjusting your search terms' : 'Get started by adding your first employee'}
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              // Actual employee data - SIMPLIFIED ACTION BUTTONS
              sortedEmployees.map(employee => (
                <tr key={employee._id || employee.employeeId} className="employee-row">
                  <td>
                    <div className="employee-id">{employee.employeeId}</div>
                  </td>
                  <td>
                    <div className="employee-info-compact">
                      <div className="employee-name">{employee.name}</div>
                      <div className="employee-email">{employee.email}</div>
                    </div>
                  </td>
                  <td>{employee.designation}</td>
                  <td>
                    <span className="department-badge">{employee.department}</span>
                  </td>
                  <td>
                    <span className={`status-badge ${employee.status === 'Active' ? 'status-active' : 'status-inactive'}`}>
                      {employee.status}
                    </span>
                  </td>
                  <td>
                    <div className="action-buttons">
                      {/* Edit Button - Simple text version */}
                      <button
                        className="action-btn edit-btn"
                        onClick={() => handleEditEmployee(employee)}
                        title="Edit Employee"
                      >
                        Edit
                      </button>
                     
                      {/* Status Change Button - Simple text version */}
                      {activeTab === 'active' ? (
                        <button
                          className="action-btn deactivate-btn"
                          onClick={() => handleStatusChange(employee.employeeId, 'Active', 'Inactive')}
                          title="Deactivate Employee"
                          style={{
                            padding: '6px 12px',
                            fontSize: '12px',
                            fontWeight: '600'
                          }}
                        >
                          Deactivate
                        </button>
                      ) : (
                        <button
                          className="action-btn activate-btn"
                          onClick={() => handleStatusChange(employee.employeeId, 'Inactive', 'Active')}
                          title="Activate Employee"
                          style={{
                            padding: '6px 12px',
                            fontSize: '12px',
                            fontWeight: '600'
                          }}
                        >
                          Activate
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add/Edit Employee Modal */}
      {showAddForm && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>{editingEmployee ? 'Edit Employee' : 'Add New Employee'}</h3>
              <button className="close-btn" onClick={handleCloseModal}>×</button>
            </div>
           
            <form className="employee-form" onSubmit={editingEmployee ? handleUpdateEmployee : handleAddEmployee}>
              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="personId">Employee ID</label>
                  <input
                    type="text"
                    id="personId"
                    name="personId"
                    value={formData.personId}
                    readOnly
                    className="readonly-input"
                  />
                  <small>Auto-generated employee ID</small>
                </div>
               
                <div className="form-group">
                  <label htmlFor="name">Full Name *</label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    placeholder="Enter full name"
                    required
                  />
                </div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="email">Email Address *</label>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    placeholder="Enter email address"
                    required
                  />
                </div>
               
                <div className="form-group">
                  <label htmlFor="password">
                    {editingEmployee ? 'New Password (leave blank to keep current)' : 'Password *'}
                  </label>
                  <input
                    type="password"
                    id="password"
                    name="password"
                    value={formData.password}
                    onChange={handleInputChange}
                    placeholder={editingEmployee ? "Enter new password" : "Enter password"}
                    pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,14}$"
                    title="Password must be 6-14 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character"
                    minLength="6"
                    required={!editingEmployee}
                  />
                  <small>Password must be 6-14 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character</small>
                </div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="designation">Designation *</label>
                  <select
                    id="designation"
                    name="designation"
                    value={formData.designation}
                    onChange={handleInputChange}
                    required
                  >
                    <option value="">Select Designation</option>
                    {designationOptions.map(designation => (
                      <option key={designation} value={designation}>{designation}</option>
                    ))}
                  </select>
                </div>
               
                <div className="form-group">
                  <label htmlFor="department">Department *</label>
                  <select
                    id="department"
                    name="department"
                    value={formData.department}
                    onChange={handleInputChange}
                    required
                  >
                    <option value="">Select Department</option>
                    {departmentOptions.map(dept => (
                      <option key={dept} value={dept}>{dept}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="phone">Phone Number *</label>
                  <div className="phone-input-container">
                    <PhoneInput
                      international
                      countryCallingCodeEditable={true}
                      defaultCountry="IN"
                      value={formData.phone}
                      onChange={handlePhoneChange}
                      placeholder="Enter phone number"
                      className={`custom-phone-input ${phoneError ? 'invalid-input' : ''}`}
                    />
                  </div>
                  {phoneError && (
                    <small className="error-text" style={{ color: '#dc2626', marginTop: '4px' }}>
                      {phoneError}
                    </small>
                  )}
                  <small style={{ color: '#64748b', marginTop: phoneError ? '2px' : '6px' }}>
                    Select country code and enter phone number
                  </small>
                </div>
               
                <div className="form-group">
                  <label htmlFor="panNumber">PAN Number *</label>
                  <input
                    type="text"
                    id="panNumber"
                    name="panNumber"
                    value={formData.panNumber}
                    onChange={handleInputChange}
                    placeholder="Enter PAN number (e.g., ABCDE1234F)"
                    pattern="[A-Z]{5}[0-9]{4}[A-Z]{1}"
                    title="Please enter a valid PAN number (e.g., ABCDE1234F)"
                    required
                    maxLength="10"
                    className={formData.panNumber && !validatePanNumber(formData.panNumber) ? 'invalid-input' : ''}
                  />
                  <small>Format: ABCDE1234F (5 letters, 4 digits, 1 letter)</small>
                </div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="joiningDate">Joining Date *</label>
                  <input
                    type="date"
                    id="joiningDate"
                    name="joiningDate"
                    value={formData.joiningDate}
                    onChange={handleInputChange}
                    required
                  />
                </div>
              </div>

              <div className="form-row">
                <div className="form-group full-width">
                  <label htmlFor="address">Address *</label>
                  <textarea
                    id="address"
                    name="address"
                    value={formData.address}
                    onChange={handleInputChange}
                    placeholder="Enter full address"
                    rows="3"
                    required
                  />
                </div>
              </div>

              {editingEmployee && (
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="status">Status</label>
                    <select
                      id="status"
                      name="status"
                      value={formData.status}
                      onChange={handleInputChange}
                    >
                      <option value="Active">Active</option>
                      <option value="Inactive">Inactive</option>
                    </select>
                  </div>
                </div>
              )}

              <div className="form-actions">
                <button
                  type="button"
                  className="cancel-btn"
                  onClick={handleCloseModal}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="submit-btn"
                  disabled={loading || (formData.panNumber && !validatePanNumber(formData.panNumber)) || phoneError}
                >
                  {loading ? 'Saving...' : (editingEmployee ? 'Update Employee' : 'Add Employee')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default EmployeeManagement;