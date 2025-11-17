import React, { useState, useEffect } from 'react';
import {
  billingService,
  currencySymbols,
  currencyOptions,
  defaultInvoiceItem,
  formatCurrencyDisplay,
  checkInvoiceStatus,
  formatInvoiceAmount,
  calculateInvoiceTotals,
  validateFile,
  getDefaultDates
} from '../../services/invoice';
import './ReportsBilling.css';

const ReportsBilling = () => {
  const [customers, setCustomers] = useState([]);
  const [invoices, setInvoices] = useState([]);
  const [disabledInvoices, setDisabledInvoices] = useState([]);
  const [selectedCustomer, setSelectedCustomer] = useState('');
  const [items, setItems] = useState([defaultInvoiceItem]);
  const [invoiceDate, setInvoiceDate] = useState('');
  const [dueDate, setDueDate] = useState('');
  const [taxPercent, setTaxPercent] = useState(0);
  const [notes, setNotes] = useState('');
  const [loading, setLoading] = useState(false);
  const [showItemsTable, setShowItemsTable] = useState(false);
  const [currency, setCurrency] = useState('USD');
  const [showInvoiceModal, setShowInvoiceModal] = useState(false);
  const [showPaymentModal, setShowPaymentModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false); // NEW: Edit modal state
  const [selectedInvoice, setSelectedInvoice] = useState(null);
  const [editingInvoice, setEditingInvoice] = useState(null); // NEW: Invoice being edited
  const [transactionNumber, setTransactionNumber] = useState('');
  const [transactionProof, setTransactionProof] = useState(null);
  const [activeTab, setActiveTab] = useState('active'); // 'active' or 'disabled'
 
  // New states for Profit & Loss report
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [reportLoading, setReportLoading] = useState(false);

  // Load customers and invoices
  useEffect(() => {
    const fetchData = async () => {
      try {
        const customersData = await billingService.getCustomers();
        setCustomers(customersData);

        const invoicesData = await billingService.getInvoices();
        setInvoices(invoicesData.filter(invoice => !invoice.isDisabled));

        const disabledInvoicesData = await billingService.getDisabledInvoices();
        setDisabledInvoices(disabledInvoicesData);

        // Set default dates
        const { today, firstDay } = getDefaultDates();
        setInvoiceDate(today);
        setStartDate(firstDay);
        setEndDate(today);
      } catch (error) {
        console.error("Error fetching data:", error);
        alert("Error fetching data");
      }
    };

    fetchData();
  }, []);

  // Handle Profit & Loss Excel download
  const handleDownloadExcel = async () => {
    if (!startDate || !endDate) {
      alert('Please select both start and end dates');
      return;
    }

    setReportLoading(true);
    try {
      const response = await billingService.downloadProfitLossExcel(startDate, endDate);

      // Download Excel
      const blob = new Blob([response.data], {
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `profit-loss-report-${startDate}-to-${endDate}.xlsx`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
     
    } catch (error) {
      console.error('Error downloading Excel report:', error);
      alert('Error downloading Excel report. Please try again.');
    } finally {
      setReportLoading(false);
    }
  };

  // Handle invoice download
  const handleDownloadInvoice = async (invoiceId) => {
    try {
      const response = await billingService.downloadInvoice(invoiceId);

      // Download PDF
      const blob = new Blob([response.data], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `Invoice-${invoiceId}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error("Error downloading invoice:", error);
      alert("Error downloading invoice. Please try again.");
    }
  };

  // Function to view payment proof
  const handleViewPaymentProof = async (invoice) => {
    if (!invoice.paymentDetails?.proofFile?.fileUrl) {
      alert('No payment proof available');
      return;
    }

    try {
      // Construct the full URL to the payment proof
      const proofUrl = `http://localhost:5000${invoice.paymentDetails.proofFile.fileUrl}`;
     
      // Open the payment proof in a new tab
      window.open(proofUrl, '_blank');
    } catch (error) {
      console.error('Error viewing payment proof:', error);
      alert('Error viewing payment proof');
    }
  };

  // NEW: Open edit invoice modal
  const handleEditInvoice = (invoice) => {
    setEditingInvoice(invoice);
    setSelectedCustomer(invoice.customerId._id);
    setItems(invoice.items.map(item => ({
      description: item.description,
      remarks: item.remarks || "",
      amount: item.amount.toString()
    })));
    setInvoiceDate(new Date(invoice.date).toISOString().split('T')[0]);
    setDueDate(invoice.dueDate ? new Date(invoice.dueDate).toISOString().split('T')[0] : '');
    setTaxPercent(invoice.taxPercent || 0);
    setNotes(invoice.notes || '');
    setCurrency(invoice.currency || 'USD');
    setShowItemsTable(true);
    setShowEditModal(true);
  };

  // NEW: Handle update invoice
  const handleUpdateInvoice = async () => {
    if (!selectedCustomer) {
      alert("Please select a customer.");
      return;
    }

    // if (!dueDate) {
    //   alert("Please select a due date.");
    //   return;
    // }

    const invalidItems = items.some((item) => !item.description.trim() || !item.amount || item.amount <= 0);
    if (invalidItems) {
      alert("Please enter valid item descriptions and amounts.");
      return;
    }

    setLoading(true);
    try {
      const invoiceData = {
        customerId: selectedCustomer,
        items: items.map((item) => ({
          description: item.description,
          remarks: item.remarks,
          amount: Number(item.amount),
        })),
        totalAmount: totals.total,
        invoiceDate,
        dueDate,
        taxPercent: Number(taxPercent),
        notes,
        currency: currency,
      };

      await billingService.updateInvoice(editingInvoice._id, invoiceData);
     
      alert("Invoice updated successfully!");
     
      // Refresh invoices list
      const invoicesData = await billingService.getInvoices();
      setInvoices(invoicesData.filter(invoice => !invoice.isDisabled));
     
      // Close modal and reset form
      closeEditModal();
    } catch (error) {
      console.error("Error updating invoice:", error);
      alert("Error updating invoice. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  // NEW: Close edit modal
  const closeEditModal = () => {
    setShowEditModal(false);
    setEditingInvoice(null);
    setItems([defaultInvoiceItem]);
    setSelectedCustomer('');
    setNotes("");
    setTaxPercent(0);
    setCurrency('USD');
    setShowItemsTable(false);
  };

  // Disable invoice (move to disabled)
  const handleDisableInvoice = async (invoiceId) => {
    if (window.confirm('Are you sure you want to move this invoice to disabled invoices?')) {
      try {
        await billingService.disableInvoice(invoiceId);
        // Update local state
        const invoiceToDisable = invoices.find(invoice => invoice._id === invoiceId);
        setInvoices(invoices.filter(invoice => invoice._id !== invoiceId));
        setDisabledInvoices([...disabledInvoices, { ...invoiceToDisable, isDisabled: true }]);
        alert('Invoice moved to disabled invoices');
      } catch (error) {
        console.error("Error disabling invoice:", error);
        alert("Error disabling invoice. Please try again.");
      }
    }
  };

  // Restore disabled invoice
  const handleRestoreInvoice = async (invoiceId) => {
    try {
      await billingService.restoreInvoice(invoiceId);
      // Update local state
      const invoiceToRestore = disabledInvoices.find(invoice => invoice._id === invoiceId);
      setDisabledInvoices(disabledInvoices.filter(invoice => invoice._id !== invoiceId));
      setInvoices([...invoices, { ...invoiceToRestore, isDisabled: false }]);
      alert('Invoice restored successfully');
    } catch (error) {
      console.error("Error restoring invoice:", error);
      alert("Error restoring invoice. Please try again.");
    }
  };

  // Permanently delete invoice
  const handlePermanentDelete = async (invoiceId) => {
    if (window.confirm('Are you sure you want to permanently delete this invoice? This action cannot be undone.')) {
      try {
        await billingService.permanentDeleteInvoice(invoiceId);
        // Remove from local state
        setDisabledInvoices(disabledInvoices.filter(invoice => invoice._id !== invoiceId));
        alert('Invoice permanently deleted');
      } catch (error) {
        console.error("Error permanently deleting invoice:", error);
        alert("Error deleting invoice. Please try again.");
      }
    }
  };

  // Open payment verification modal
  const openPaymentModal = (invoice) => {
    setSelectedInvoice(invoice);
    setShowPaymentModal(true);
  };

  // Close payment verification modal
  const closePaymentModal = () => {
    setShowPaymentModal(false);
    setSelectedInvoice(null);
    setTransactionNumber('');
    setTransactionProof(null);
  };

  // Handle file upload for transaction proof
  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      try {
        validateFile(file, 10);
        setTransactionProof(file);
      } catch (error) {
        alert(error.message);
      }
    }
  };

  // Handle payment verification
  const handleVerifyPayment = async () => {
    if (!transactionNumber.trim()) {
      alert('Please enter a transaction number');
      return;
    }

    if (!transactionProof) {
      alert('Please upload proof of transaction');
      return;
    }

    setLoading(true);
    try {
      const paymentData = {
        invoiceId: selectedInvoice._id,
        transactionNumber,
        transactionProof
      };

      const result = await billingService.verifyPayment(paymentData);

      // Update invoice with complete data including payment details
      setInvoices(invoices.map(inv =>
        inv._id === selectedInvoice._id
          ? result.invoice // Use the complete invoice data from response
          : inv
      ));

      alert('Payment verified successfully!');
      closePaymentModal();
    } catch (error) {
      console.error('Error verifying payment:', error);
      alert('Error verifying payment. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Add / Remove / Edit items
  const handleAddItem = () => {
   const newItem = { ...defaultInvoiceItem };
  setItems([...items, newItem]);
  setShowItemsTable(true);
  };

  const handleRemoveItem = (index) => {
    const newItems = items.filter((_, i) => i !== index);
    setItems(newItems);
    if (newItems.length === 0) {
      setShowItemsTable(false);
    }
  };

  const handleItemChange = (index, field, value) => {
  const newItems = [...items];
  newItems[index] = { ...newItems[index], [field]: value }; // ensure immutability
  setItems(newItems);
  };

  // Total calculation using service function
  const totals = calculateInvoiceTotals(items, taxPercent, currency);

  // Open invoice modal
  const openInvoiceModal = () => {
    setShowInvoiceModal(true);
  };

  // Close invoice modal and reset form
  const closeInvoiceModal = () => {
    setShowInvoiceModal(false);
    setItems([defaultInvoiceItem]);
    setSelectedCustomer('');
    setNotes("");
    setTaxPercent(0);
    setCurrency('USD');
    setShowItemsTable(false);
  };

  // Invoice generation
  const handleGenerateInvoice = async () => {
    if (!selectedCustomer) {
      alert("Please select a customer.");
      return;
    }

    // if (!dueDate) {
    //   alert("Please select a due date.");
    //   return;
    // }

    const invalidItems = items.some((item) => !item.description.trim() || !item.amount || item.amount <= 0);
    if (invalidItems) {
      alert("Please enter valid item descriptions and amounts.");
      return;
    }

    setLoading(true);
    try {
      const invoiceData = {
        customerId: selectedCustomer,
        items: items.map((item) => ({
          description: item.description,
          remarks: item.remarks,
          amount: Number(item.amount),
        })),
        totalAmount: totals.total,
        invoiceDate,
        dueDate,
        taxPercent: Number(taxPercent),
        notes,
        currency: currency,
      };

      const response = await billingService.generateInvoice(invoiceData);

      // Download PDF
      const blob = new Blob([response.data], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `Invoice-${new Date().toISOString().split("T")[0]}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();

      alert("Invoice generated successfully!");
     
      // Refresh invoices list
      const invoicesData = await billingService.getInvoices();
      setInvoices(invoicesData.filter(invoice => !invoice.isDisabled));
     
      // Close modal and reset form
      closeInvoiceModal();
    } catch (error) {
      console.error("Error generating invoice:", error);
      alert("Error generating invoice. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  // Get all invoices sorted by date (newest first)
  const getAllInvoices = () => {
    return invoices.sort((a, b) => new Date(b.date) - new Date(a.date));
  };

  // Get disabled invoices sorted by date (newest first)
  const getDisabledInvoicesList = () => {
    return disabledInvoices.sort((a, b) => new Date(b.date) - new Date(a.date));
  };

  return (
    <div className="reports-billing-container">
      {/* Header Section */}
      {/* <div className="reports-header">
        <div className="header-content">
          <div className="header-text">
          </div>
        </div>
      </div> */}
     
      {/* Main Content Grid */}
      <div className="main-content-grid">
        {/* Top Section with Profit & Loss */}
          <div className="profit-loss-section">
            {/* <div className="report-card"> */}
             
              <div className="form-section">
                <div className="card-header">
                <h3>Profit & Loss Report</h3>
              </div>
                <div className="form-field">
                  <label>Date Range</label>
                  <div className="date-range">
                    <input
                      type="date"
                      className="date-input"
                      value={startDate}
                      onChange={(e) => setStartDate(e.target.value)}
                    />
                    <span>to</span>
                    <input
                      type="date"
                      className="date-input"
                      value={endDate}
                      onChange={(e) => setEndDate(e.target.value)}
                    />
                  </div>
                </div>
               
                <div className="export-buttons">
                  <button
                    className="export-btn excel"
                    onClick={handleDownloadExcel}
                    disabled={reportLoading || !startDate || !endDate}
                  >
                    {reportLoading ? 'Generating...' : 'Excel'}
                  </button>
                </div>
              </div>
            {/* </div> */}
          </div>
     

        {/* Invoice History / Disabled Invoices */}
        <div className="report-card invoice-history-card">
          <div className="card-header responsive-header">
            <div className="tab-navigation">
              <button
                className={`tab-button ${activeTab === 'active' ? 'active' : ''}`}
                onClick={() => setActiveTab('active')}
              >
                Invoice History
              </button>
              <button
                className={`tab-button ${activeTab === 'disabled' ? 'active' : ''}`}
                onClick={() => setActiveTab('disabled')}
              >
                Disabled Invoices
              </button>
            </div>
            <button className="generate-invoice-main-btn" onClick={openInvoiceModal}>
              Generate New Invoice
            </button>
          </div>
         
          <div className="invoice-history-table responsive-table-container">
            <table className="responsive-table">
              <thead>
                <tr>
                  <th className="column-invoice">Invoice Number</th>
                  <th className="column-customer">Customer</th>
                  <th className="column-date">Date</th>
                  <th className="column-status">Status</th>
                  <th className="column-amount">Amount</th>
                  <th className="column-actions">Actions</th>
                </tr>
              </thead>
              <tbody>
                {activeTab === 'active' ? (
                  // Active Invoices
                  getAllInvoices().map(invoice => {
                    const status = checkInvoiceStatus(invoice);
                    return (
                      <tr key={invoice._id}>
                        <td className="invoice-number" data-label="Invoice Number">
                          {invoice.invoiceNumber || `INV-${invoice._id.toString().slice(-6).toUpperCase()}`}
                        </td>
                        <td className="customer-info" data-label="Customer">
                          <div className="customer-name">{invoice.customerId?.name || 'N/A'}</div>
                          <div className="customer-id">{invoice.customerId?.customerId || ''}</div>
                        </td>
                        <td className="invoice-date" data-label="Date">
                          {new Date(invoice.date).toLocaleDateString()}
                        </td>
                        <td className="invoice-status" data-label="Status">
                          <span className={`status-badge ${status}`}>
                            {status === 'overdue' ? 'Overdue' :
                             status === 'paid' ? 'Paid' : 'Unpaid'}
                          </span>
                        </td>
                        <td className="amount" data-label="Amount">
                          {currencySymbols[invoice.currency] || '$'}{formatInvoiceAmount(invoice)}
                        </td>
                        <td className="invoice-actions" data-label="Actions">
                          <div className="inv-action-buttons responsive-actions">
                            {/* NEW: Edit Button */}
                            <button
                              className="inv-action-btn edit"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleEditInvoice(invoice);
                              }}
                              title="Edit Invoice"
                            >
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                              </svg>
                            </button>

                            <button
                              className="inv-action-btn download"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDownloadInvoice(invoice._id);
                              }}
                              title="Download Invoice"
                            >
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="7 10 12 15 17 10"></polyline>
                                <line x1="12" y1="15" x2="12" y2="3"></line>
                              </svg>
                            </button>
                           
                            {/* View Payment Proof Button - Only for paid invoices with proof */}
                            {invoice.status === 'paid' && invoice.paymentDetails?.proofFile && (
                            <button
                              className="inv-action-btn view-proof"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleViewPaymentProof(invoice);
                              }}
                              title="View Payment Proof"
                            >
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                              </svg>
                            </button>
                          )}
                         
                          {/* Verify Payment Button - Only for unpaid/overdue invoices */}
                          {(status === 'unpaid' || status === 'overdue') && (
                            <button
                              className="inv-action-btn verify-payment"
                              onClick={(e) => {
                                e.stopPropagation();
                                openPaymentModal(invoice);
                              }}
                              title="Verify Payment"
                            >
                              Verify
                            </button>
                          )}
                         
                          <button
                            className="inv-action-btn disable"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDisableInvoice(invoice._id);
                            }}
                            title="Disable Invoice"
                          >
                            Disable
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
                ) : (
                  // Disabled Invoices
                  getDisabledInvoicesList().map(invoice => {
                    const status = checkInvoiceStatus(invoice);
                    return (
                      <tr key={invoice._id} className="disabled-row">
                        <td className="invoice-number" data-label="Invoice Number">
                          {invoice.invoiceNumber || `INV-${invoice._id.toString().slice(-6).toUpperCase()}`}
                        </td>
                        <td className="customer-info" data-label="Customer">
                          <div className="customer-name">{invoice.customerId?.name || 'N/A'}</div>
                          <div className="customer-id">{invoice.customerId?.customerId || ''}</div>
                        </td>
                        <td className="invoice-date" data-label="Date">
                          {new Date(invoice.date).toLocaleDateString()}
                        </td>
                        <td className="invoice-status" data-label="Status">
                          <span className={`status-badge ${status} disabled`}>
                            {status === 'overdue' ? 'Overdue' :
                             status === 'paid' ? 'Paid' : 'Unpaid'}
                          </span>
                        </td>
                        <td className="amount" data-label="Amount">
                          {currencySymbols[invoice.currency] || '$'}{formatInvoiceAmount(invoice)}
                        </td>
                        <td className="invoice-actions" data-label="Actions">
                          <div className="inv-action-buttons responsive-actions">
                            <button
                              className="inv-action-btn restore"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleRestoreInvoice(invoice._id);
                              }}
                              title="Restore Invoice"
                            >
                              Restore
                            </button>
                           
                            <button
                              className="inv-action-btn permanent-delete"
                              onClick={(e) => {
                                e.stopPropagation();
                                handlePermanentDelete(invoice._id);
                              }}
                              title="Permanently Delete"
                            >
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M3 6h18"></path>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"></path>
                                <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                <line x1="10" y1="11" x2="10" y2="17"></line>
                                <line x1="14" y1="11" x2="14" y2="17"></line>
                              </svg>
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
                {(activeTab === 'active' && getAllInvoices().length === 0) ||
                 (activeTab === 'disabled' && getDisabledInvoicesList().length === 0) && (
                  <tr>
                    <td colSpan="6" className="no-data-message">
                      {activeTab === 'active' ? 'No active invoices found' : 'No disabled invoices found'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Invoice Generation Modal */}
      {showInvoiceModal && (
        <div className="modal-overlay" onClick={closeInvoiceModal}>
          <div className="modal-content responsive-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Generate New Invoice</h2>
              <button className="close-modal-btn" onClick={closeInvoiceModal}>
                ×
              </button>
            </div>
           
            <div className="modal-body">
              <div className="report-card invoice-generation-card">
                <div className="card-header">
                  <h3>Invoice Details</h3>
                  <p>Create and manage customer invoices</p>
                </div>
               
                <div className="form-section">
                  <div className="form-field">
                    <label className="required">Select Customer</label>
                    <select
                      className="form-select"
                      value={selectedCustomer}
                      onChange={(e) => setSelectedCustomer(e.target.value)}
                      required
                    >
                      <option value="">-- Select Customer --</option>
                      {customers.map(customer => (
                        <option key={customer._id} value={customer._id}>
                          {customer.name} {customer.company ? `- ${customer.company}` : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                 
                  <div className="form-grid-2 responsive-form-grid">
                    <div className="form-field">
                      <label className="required">Invoice Date</label>
                      <input
                        type="date"
                        className="form-input"
                        value={invoiceDate}
                        onChange={(e) => setInvoiceDate(e.target.value)}
                      />
                    </div>
                   
                    <div className="form-field">
                      <label className>Due Date</label>
                      <input
                        type="date"
                        className="form-input"
                        value={dueDate}
                        onChange={(e) => setDueDate(e.target.value)}
                        //required
                      />
                    </div>
                  </div>

                  <div className="form-field">
                    <label>Currency</label>
                    <select
                      className="form-select"
                      value={currency}
                      onChange={(e) => setCurrency(e.target.value)}
                    >
                      {currencyOptions.map(option => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="form-field">
                    <label>Tax (%)</label>
                    <input
                      type="number"
                      className="form-input"
                      value={taxPercent}
                      onChange={(e) => setTaxPercent(e.target.value)}
                      placeholder="e.g. 10"
                      min="0"
                      max="100"
                      step="0.01"
                    />
                  </div>
                 
                  {/* Items Section */}
                  <div className="invoice-items-section">
                    <div className="section-header">
                      <label className="required">Invoice Items</label>
                      <button onClick={handleAddItem} className="add-item-btn">
                        + Add Item
                      </button>
                    </div>
                   
                    {showItemsTable && (
                      <div className="invoice-items-table responsive-table-container">
                        <table className="responsive-table">
                          <thead>
                            <tr>
                              <th className="column-description">Description</th>
                              <th className="column-remarks">Remarks</th>
                              <th className="column-amount">Amount ({currencySymbols[currency]})</th>
                              <th className="column-action">Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {items.map((item, index) => (
                              <tr key={index}>
                                <td data-label="Description">
                                  <input
                                    type="text"
                                    placeholder="Item description"
                                    value={item.description}
                                    onChange={(e) => handleItemChange(index, "description", e.target.value)}
                                    className="table-input"
                                    required
                                  />
                                </td>
                                <td data-label="Remarks">
                                  <input
                                    type="text"
                                    placeholder="Additional remarks"
                                    value={item.remarks}
                                    onChange={(e) => handleItemChange(index, "remarks", e.target.value)}
                                    className="table-input remarks-input"
                                  />
                                </td>
                                <td data-label={`Amount (${currencySymbols[currency]})`}>
                                  <input
                                    type="number"
                                    placeholder="Amount"
                                    value={item.amount}
                                    onChange={(e) => handleItemChange(index, "amount", e.target.value)}
                                    className="table-input"
                                    min="0"
                                    step="0.01"
                                    required
                                  />
                                </td>
                                <td data-label="Action">
                                  {items.length > 1 && (
                                    <button
                                      className="remove-btn"
                                      onClick={() => handleRemoveItem(index)}
                                    >
                                      Remove
                                    </button>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  {/* Totals Summary */}
                  {showItemsTable && (
                    <div className="totals-summary">
                      <div className="summary-line">
                        <span>Subtotal:</span>
                        <span>{currencySymbols[currency]}{totals.formattedSubtotal}</span>
                      </div>
                      {taxPercent > 0 && (
                        <div className="summary-line">
                          <span>Tax ({taxPercent}%):</span>
                          <span>{currencySymbols[currency]}{totals.formattedTaxAmount}</span>
                        </div>
                      )}
                      <div className="summary-total">
                        <span>Grand Total:</span>
                        <span>{currencySymbols[currency]}{totals.formattedTotal}</span>
                      </div>
                    </div>
                  )}

                  {/* Notes */}
                  <div className="form-field">
                    <label>Additional Notes</label>
                    <textarea
                      className="form-textarea"
                      placeholder="Any additional notes..."
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                      rows="3"
                    />
                  </div>
                 
                  <button
                    className="generate-invoice-btn"
                    onClick={handleGenerateInvoice}
                    disabled={loading}
                  >
                    {loading ? "Generating..." : "Generate & Download PDF"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* NEW: Edit Invoice Modal */}
      {showEditModal && editingInvoice && (
        <div className="modal-overlay" onClick={closeEditModal}>
          <div className="modal-content responsive-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Edit Invoice - {editingInvoice.invoiceNumber}</h2>
              <button className="close-modal-btn" onClick={closeEditModal}>
                ×
              </button>
            </div>
           
            <div className="modal-body">
              <div className="report-card invoice-generation-card">
                <div className="card-header">
                  <h3>Edit Invoice Details</h3>
                  <p>Update invoice information</p>
                </div>
               
                <div className="form-section">
                  <div className="form-field">
                    <label className="required">Select Customer</label>
                    <select
                      className="form-select"
                      value={selectedCustomer}
                      onChange={(e) => setSelectedCustomer(e.target.value)}
                      required
                    >
                      <option value="">-- Select Customer --</option>
                      {customers.map(customer => (
                        <option key={customer._id} value={customer._id}>
                          {customer.name} {customer.company ? `- ${customer.company}` : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                 
                  <div className="form-grid-2 responsive-form-grid">
                    <div className="form-field">
                      <label>Invoice Date</label>
                      <input
                        type="date"
                        className="form-input"
                        value={invoiceDate}
                        onChange={(e) => setInvoiceDate(e.target.value)}
                      />
                    </div>
                   
                    <div className="form-field">
                      <label className>Due Date</label>
                      <input
                        type="date"
                        className="form-input"
                        value={dueDate}
                        onChange={(e) => setDueDate(e.target.value)}
                        // required
                      />
                    </div>
                  </div>

                  <div className="form-field">
                    <label>Currency</label>
                    <select
                      className="form-select"
                      value={currency}
                      onChange={(e) => setCurrency(e.target.value)}
                    >
                      {currencyOptions.map(option => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="form-field">
                    <label>Tax (%)</label>
                    <input
                      type="number"
                      className="form-input"
                      value={taxPercent}
                      onChange={(e) => setTaxPercent(e.target.value)}
                      placeholder="e.g. 10"
                      min="0"
                      max="100"
                      step="0.01"
                    />
                  </div>
                 
                  {/* Items Section */}
                  <div className="invoice-items-section">
                    <div className="section-header">
                      <label className="required">Invoice Items</label>
                      <button onClick={handleAddItem} className="add-item-btn">
                        + Add Item
                      </button>
                    </div>
                   
                    {showItemsTable && (
                      <div className="invoice-items-table responsive-table-container">
                        <table className="responsive-table">
                          <thead>
                            <tr>
                              <th className="column-description">Description</th>
                              <th className="column-remarks">Remarks</th>
                              <th className="column-amount">Amount ({currencySymbols[currency]})</th>
                              <th className="column-action">Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {items.map((item, index) => (
                              <tr key={index}>
                                <td data-label="Description">
                                  <input
                                    type="text"
                                    placeholder="Item description"
                                    value={item.description}
                                    onChange={(e) => handleItemChange(index, "description", e.target.value)}
                                    className="table-input"
                                    required
                                  />
                                </td>
                                <td data-label="Remarks">
                                  <input
                                    type="text"
                                    placeholder="Additional remarks"
                                    value={item.remarks}
                                    onChange={(e) => handleItemChange(index, "remarks", e.target.value)}
                                    className="table-input remarks-input"
                                  />
                                </td>
                                <td data-label={`Amount (${currencySymbols[currency]})`}>
                                  <input
                                    type="number"
                                    placeholder="Amount"
                                    value={item.amount}
                                    onChange={(e) => handleItemChange(index, "amount", e.target.value)}
                                    className="table-input"
                                    min="0"
                                    step="0.01"
                                    required
                                  />
                                </td>
                                <td data-label="Action">
                                  {items.length > 1 && (
                                    <button
                                      className="remove-btn"
                                      onClick={() => handleRemoveItem(index)}
                                    >
                                      Remove
                                    </button>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  {/* Totals Summary */}
                  {showItemsTable && (
                    <div className="totals-summary">
                      <div className="summary-line">
                        <span>Subtotal:</span>
                        <span>{currencySymbols[currency]}{totals.formattedSubtotal}</span>
                      </div>
                      {taxPercent > 0 && (
                        <div className="summary-line">
                          <span>Tax ({taxPercent}%):</span>
                          <span>{currencySymbols[currency]}{totals.formattedTaxAmount}</span>
                        </div>
                      )}
                      <div className="summary-total">
                        <span>Grand Total:</span>
                        <span>{currencySymbols[currency]}{totals.formattedTotal}</span>
                      </div>
                    </div>
                  )}

                  {/* Notes */}
                  <div className="form-field">
                    <label>Additional Notes</label>
                    <textarea
                      className="form-textarea"
                      placeholder="Any additional notes..."
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                      rows="3"
                    />
                  </div>
                 
                  <button
                    className="generate-invoice-btn"
                    onClick={handleUpdateInvoice}
                    disabled={loading}
                  >
                    {loading ? "Updating..." : "Update Invoice"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Payment Verification Modal */}
      {showPaymentModal && selectedInvoice && (
        <div className="modal-overlay" onClick={closePaymentModal}>
          <div className="modal-content payment-modal responsive-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-body">
              <div className="report-card payment-details-card">
                <div className="card-header">
                  <h3>Payment Details</h3>
                </div>
               
                <div className="form-section">
                  <div className="invoice-summary">
                    <div className="summary-row">
                      <span>Customer:</span>
                      <span>{selectedInvoice.customerId?.name || 'N/A'}</span>
                    </div>
                    <div className="summary-row">
                      <span>Amount Due:</span>
                      <span className="amount-due">
                        {currencySymbols[selectedInvoice.currency] || '$'}{formatInvoiceAmount(selectedInvoice)}
                      </span>
                    </div>
                    <div className="summary-row">
                      <span>Due Date:</span>
                      <span>{new Date(selectedInvoice.dueDate).toLocaleDateString()}</span>
                    </div>
                  </div>
                 
                  <div className="form-field">
                    <label>Transaction Number *</label>
                    <input
                      type="text"
                      className="form-input"
                      value={transactionNumber}
                      onChange={(e) => setTransactionNumber(e.target.value)}
                      placeholder="Enter transaction/reference number"
                      required
                    />
                  </div>
                 
                  <div className="form-field">
                    <label>Proof of Transaction *</label>
                    <div className="file-upload-container">
                      <input
                        type="file"
                        id="transaction-proof"
                        className="file-input"
                        onChange={handleFileUpload}
                        accept=".pdf,.jpg,.jpeg,.png,.doc,.docx"
                        required
                      />
                      <label htmlFor="transaction-proof" className="file-upload-label">
                        {transactionProof ? transactionProof.name : 'Choose file...'}
                      </label>
                      {transactionProof && (
                        <span className="file-size">
                          {(transactionProof.size / 1024 / 1024).toFixed(2)} MB
                        </span>
                      )}
                    </div>
                    <p className="file-hint">Supported formats: PDF, JPG, PNG, DOC (Max: 10MB)</p>
                  </div>
                 
                  <div className="payment-actions">
                    <button className="cancel-btn" onClick={closePaymentModal}>
                      Cancel
                    </button>
                    <button
                      className="confirm-payment-btn"
                      onClick={handleVerifyPayment}
                      disabled={loading}
                    >
                      {loading ? "Processing..." : "Confirm Payment"}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportsBilling;