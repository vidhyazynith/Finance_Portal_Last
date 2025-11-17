import api from './api';

export const employeeService = {

    async registerEmployee(employeeData) {
    const response = await api.post('/employees/register/employee', employeeData);
    return response.data;
  },
    // Get all employees (admin only)
  async getEmployees() {
    const response = await api.get('/employees');
    return response.data;
  },

  // Get employee by ID
  async getEmployeeById(employeeId) {
    const response = await api.get(`/employees/${employeeId}`);
    return response.data;
  },

  // Update employee
  async updateEmployee(employeeId, employeeData) {
    const response = await api.put(`/employees/${employeeId}`, employeeData);
    return response.data;
  },

  // Delete employee
  async deleteEmployee(employeeId) {
    
    const response = await api.delete(`/employees/${employeeId}`);
    return response.data;
  },

  //upload photo for the employee dashboard
  uploadPhoto: (formData) => api.post('/upload/photo', formData, {
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  }),
  
  removePhoto: () => api.delete('/upload/photo'),
};