import React, { useState, useEffect } from 'react';
import { transactionService, typeOptions, categoryOptions } from '../../services/transactions';
import './InOutTransactions.css';

const InOutTransactions = ({onTransactionUpdate}) => {
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [selectedTransaction, setSelectedTransaction] = useState(null);
  const [newTransaction, setNewTransaction] = useState({
    description: '',
    amount: '',
    type: '',
    category: '',
    remarks: '',
    attachment: null,
  });
  const [filterType, setFilterType] = useState('');
  const [filterCategory, setFilterCategory] = useState('');
  const [search, setSearch] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [totals, setTotals] = useState({
    income: 0,
    expenses: 0,
    net: 0
  });

  // Fetch transactions from backend
  const fetchTransactions = async () => {
    try {
      setLoading(true);
      const filters = {};
      if (filterType) filters.type = filterType;
      if (filterCategory) filters.category = filterCategory;
      if (search) filters.search = search;

      const data = await transactionService.getTransactions(filters);
      setTransactions(data.transactions || []);
      setTotals(data.totals || { income: 0, expenses: 0, net: 0 });
       if (onTransactionUpdate) {
        onTransactionUpdate();
      }
    } catch (error) {
      console.error('Error fetching transactions:', error);
      setErrorMessage('Failed to load transactions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTransactions();
  }, [filterType, filterCategory, search]);

  // Open detail view modal
  const handleViewDetails = (transaction) => {
    setSelectedTransaction(transaction);
    setDetailModalOpen(true);
  };

  // Close detail view modal
  const handleCloseDetailModal = () => {
    setDetailModalOpen(false);
    setSelectedTransaction(null);
  };

  // Download attachment
  const handleDownloadAttachment = async (transactionId, fileName) => {
    try {
      const response = await transactionService.downloadAttachment(transactionId);
      
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error downloading attachment:', error);
      setErrorMessage('Failed to download attachment');
    }
  };

  // Add new transaction
  const handleAddTransaction = async () => {
    if (!newTransaction.description || !newTransaction.amount || !newTransaction.type || !newTransaction.category) {
      setErrorMessage('Please fill in all required fields: Description, Amount, Type, and Category');
      return;
    }

    try {
      await transactionService.addTransaction(newTransaction);
      
      setSuccessMessage('Transaction added successfully!');
      setNewTransaction({ 
        description: '', 
        amount: '', 
        type: '', 
        category: '', 
        remarks: '',
        attachment: null 
      });
      setOpen(false);
      
      fetchTransactions();
         if (onTransactionUpdate) {
        onTransactionUpdate();
      }
    } catch (error) {
      console.error('Error adding transaction:', error);
      setErrorMessage('Failed to add transaction');
    }
  };

  // Delete transaction
  const handleDeleteTransaction = async (transactionId) => {
    if (window.confirm('Are you sure you want to delete this transaction?')) {
      try {
        await transactionService.deleteTransaction(transactionId);
        setSuccessMessage('Transaction deleted successfully');
        fetchTransactions();
           if (onTransactionUpdate) {
        onTransactionUpdate();
      }
      } catch (error) {
        console.error('Error deleting transaction:', error);
        setErrorMessage('Failed to delete transaction');
      }
    }
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const allowedTypes = ['.pdf', '.jpg', '.jpeg', '.png', '.doc', '.docx', '.xlsx'];
      const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
      
      if (!allowedTypes.includes(fileExtension)) {
        setErrorMessage('Please select a valid file type: PDF, JPG, PNG, DOC, DOCX, XLSX');
        return;
      }

      if (file.size > 5 * 1024 * 1024) {
        setErrorMessage('File size must be less than 5MB');
        return;
      }

      setNewTransaction({
        ...newTransaction,
        attachment: file
      });
    }
  };

  // Format date for display
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-GB');
  };

  // Format currency in Indian Rupees
  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount);
  };

  return (
    <div className="transactions-container">
      {/* <div className="transactions-header">
      </div> */}

      {/* Success/Error Messages */}
      {successMessage && (
        <div className="alert success">
          {successMessage}
          <button onClick={() => setSuccessMessage('')} className="close-alert">×</button>
        </div>
      )}
      
      {errorMessage && (
        <div className="alert error">
          {errorMessage}
          <button onClick={() => setErrorMessage('')} className="close-alert">×</button>
        </div>
      )}

      {/* Summary Cards */}
      <div className="summary-cards">
        <div className="summary-card income">
          <div className="card-icon">↑</div>
          <div className="card-content">
            <h3>Total Income</h3>
            <div className="amount">{formatCurrency(totals.income)}</div>
          </div>
        </div>
        
        <div className="summary-card expense">
          <div className="card-icon">↓</div>
          <div className="card-content">
            <h3>Total Expenses</h3>
            <div className="amount">{formatCurrency(totals.expenses)}</div>
          </div>
        </div>
        
        <div className="summary-card net">
          <div className="card-icon">📊</div>
          <div className="card-content">
            <h3>Net Income</h3>
            <div className={`amount ${totals.net >= 0 ? 'positive' : 'negative'}`}>
              {formatCurrency(totals.net)}
            </div>
          </div>
        </div>
      </div>

      {/* Transaction History Header */}
      <div className="transaction-history-header">
        <h2>Transaction History ({transactions.length} records)</h2>
        <button className="add-transaction-btn" onClick={() => setOpen(true)}>
          + Add Transaction
        </button>
      </div>

      {/* Search and Filters */}
      <div className="filters-section">
        <input
          type="text"
          className="search-input"
          placeholder="Search transactions or remarks"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select 
          className="filter-select"
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
        >
          <option value="">Type</option>
          {typeOptions.map((type) => (
            <option key={type} value={type}>{type}</option>
          ))}
        </select>
        <select 
          className="filter-select"
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value)}
        >
          <option value="">Category</option>
          {categoryOptions.map((cat) => (
            <option key={cat} value={cat}>{cat}</option>
          ))}
        </select>
      </div>

      {/* Transactions Table */}
      <div className="transactions-table-container">
        {loading ? (
          <div className="loading">Loading transactions...</div>
        ) : (
          <table className="transactions-table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Description</th>
                <th>Category</th>
                <th>Amount</th>
                <th>Remarks</th>
                <th>Attachment</th>
                <th>Type</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {transactions.map((transaction) => (
                <tr key={transaction._id} onClick={() => handleViewDetails(transaction)}>
                  <td>{formatDate(transaction.date)}</td>
                  <td className="description-cell">{transaction.description}</td>
                  <td>
                    <span className={`category-tag ${transaction.type.toLowerCase()}`}>
                      {transaction.category}
                    </span>
                  </td>
                  <td className={`amount-cell ${transaction.type.toLowerCase()}`}>
                    {formatCurrency(transaction.amount)}
                  </td>
                  <td className="remarks-cell">
                    {transaction.remarks || 'No remarks'}
                  </td>
                  <td className="attachment-cell">
                    {transaction.attachment ? (
                      <div className="file-attachment">
                        <span className="file-icon">📁</span>
                        <span className="file-name">{transaction.attachment.originalName}</span>
                      </div>
                    ) : (
                      <span className="no-file">No file</span>
                    )}
                  </td>
                  <td>
                    <span className={`type-badge ${transaction.type.toLowerCase()}`}>
                      {transaction.type}
                    </span>
                  </td>
                  <td className="actions-cell">
                    <button 
                      className="action-btn-view-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleViewDetails(transaction);
                      }}
                      title="View Details"
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                        <circle cx="12" cy="12" r="3"></circle>
                      </svg>
                    </button>
                    <button 
                      className="action-btn-delete-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteTransaction(transaction._id);
                      }}
                      title="Delete"
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M3 6h18"></path>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"></path>
                        <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        <line x1="10" y1="11" x2="10" y2="17"></line>
                        <line x1="14" y1="11" x2="14" y2="17"></line>
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Add Transaction Modal */}
      {open && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h2>Add New Transaction</h2>
              <button className="close-btn" onClick={() => setOpen(false)}>×</button>
            </div>
            
            <div className="modal-body">
              <div className="form-group">
                <label className="required">Description</label>
                <input
                  type="text"
                  className="form-input"
                  value={newTransaction.description}
                  onChange={(e) => setNewTransaction({ ...newTransaction, description: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="required">Amount</label>
                <input
                  type="number"
                  className="form-input"
                  value={newTransaction.amount}
                  onChange={(e) => setNewTransaction({ ...newTransaction, amount: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="required">Type</label>
                <select
                  className="form-select"
                  value={newTransaction.type}
                  onChange={(e) => setNewTransaction({ ...newTransaction, type: e.target.value })}
                  required
                >
                  <option value="">Select Type</option>
                  {typeOptions.map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label className="required">Category</label>
                <select
                  className="form-select"
                  value={newTransaction.category}
                  onChange={(e) => setNewTransaction({ ...newTransaction, category: e.target.value })}
                  required
                >
                  <option value="">Select Category</option>
                  {categoryOptions.map((cat) => (
                    <option key={cat} value={cat}>{cat}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>Remarks</label>
                <textarea
                  className="form-textarea"
                  value={newTransaction.remarks}
                  onChange={(e) => setNewTransaction({ ...newTransaction, remarks: e.target.value })}
                  rows="3"
                  placeholder="Add any additional notes or details..."
                />
              </div>

              <div className="form-group">
                <label>Attach Receipt (Optional)</label>
                <div className="file-upload-section">
                  <input
                    type="file"
                    id="attachment-upload"
                    className="file-input"
                    accept=".pdf,.jpg,.jpeg,.png,.doc,.docx,.xlsx"
                    onChange={handleFileUpload}
                  />
                  <label htmlFor="attachment-upload" className="file-upload-label">
                    {newTransaction.attachment ? `📁 ${newTransaction.attachment.name}` : 'CHOOSE FILE (PDF, IMAGE, DOCUMENT)'}
                  </label>
                  <p className="file-hint">Max file size: 5MB • Supported: PDF, JPG, PNG, DOC, XLSX</p>
                </div>
              </div>
            </div>

            <div className="modal-actions">
              <button className="btn-cancel" onClick={() => setOpen(false)}>
                CANCEL
              </button>
              <button 
                className="btn-primary"
                onClick={handleAddTransaction}
                disabled={!newTransaction.description || !newTransaction.amount || !newTransaction.type || !newTransaction.category}
              >
                ADD TRANSACTION
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Transaction Details Modal */}
      {detailModalOpen && selectedTransaction && (
        <div className="modal-overlay">
          <div className="modal-content details-modal">
            <div className="modal-header">
              <h2>Transaction Details</h2>
              <p className="read-only-note">Read Only - No editing allowed</p>
              <button className="close-btn" onClick={handleCloseDetailModal}>×</button>
            </div>
            
            <div className="modal-body">
              <div className="details-grid">
                <div className="details-column">
                  <div className="detail-item">
                    <label>Date</label>
                    <p>{formatDate(selectedTransaction.date)}</p>
                  </div>
                  <div className="detail-item">
                    <label>Description</label>
                    <p>{selectedTransaction.description}</p>
                  </div>
                  <div className="detail-item">
                    <label>Category</label>
                    <span className={`category-tag ${selectedTransaction.type.toLowerCase()}`}>
                      {selectedTransaction.category}
                    </span>
                  </div>
                  <div className="detail-item">
                    <label>Type</label>
                    <span className={`type-badge ${selectedTransaction.type.toLowerCase()}`}>
                      {selectedTransaction.type}
                    </span>
                  </div>
                </div>
                
                <div className="details-column">
                  <div className="detail-item">
                    <label>Amount</label>
                    <p className={`amount-large ${selectedTransaction.type.toLowerCase()}`}>
                      {formatCurrency(selectedTransaction.amount)}
                    </p>
                  </div>
                  <div className="detail-item">
                    <label>Attachment</label>
                    {selectedTransaction.attachment ? (
                      <div className="attachment-details">
                        <span className="file-icon">📁</span>
                        <span className="file-name">{selectedTransaction.attachment.originalName}</span>
                        <button 
                          className="download-btn"
                          onClick={() => handleDownloadAttachment(selectedTransaction._id, selectedTransaction.attachment.originalName)}
                        >
                          Download
                        </button>
                      </div>
                    ) : (
                      <p className="no-attachment">No attachment</p>
                    )}
                  </div>
                </div>
              </div>

              <div className="remarks-section">
                <label>Remarks</label>
                <div className="remarks-box">
                  {selectedTransaction.remarks || 'No remarks provided'}
                </div>
              </div>
            </div>

            <div className="modal-actions">
              <button className="btn-primary full-width" onClick={handleCloseDetailModal}>
                CLOSE DETAILS
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default InOutTransactions;