import mongoose from "mongoose";

const invoiceSchema = new mongoose.Schema({
  invoiceNumber: { type: String, unique: true },
  customerId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "Customer", 
    required: true 
  },
  items: [{
    description: { type: String, required: true },
    remarks: { type: String, default: "" },
    amount: { type: Number, required: true }
  }],
  subtotal: { type: Number, required: true },
  taxPercent: { type: Number, default: 0 },
  taxAmount: { type: Number, default: 0 },
  totalAmount: { type: Number, required: true },
  date: { type: Date, default: Date.now },
  dueDate: { type: Date },
  notes: { type: String },
  status: { 
    type: String, 
    enum: ["sent", "paid", "overdue"], 
    default: "sent" 
  },
  currency: {
    type: String,
    enum: ["USD", "EUR", "INR"],
    default: "USD",
  },
  paymentDetails: {
    transactionNumber: { type: String },
    verifiedAt: { type: Date },
    proofFile: {
      originalName: { type: String },
      mimeType: { type: String },
      size: { type: Number },
      uploadedAt: { type: Date },
      fileName: { type: String },
      filePath: { type: String },
      fileUrl: { type: String }
    }
  },
  // FIXED: Changed to false and added isDisabled field for better clarity
  deleted: { type: Boolean, default: false },
  isDisabled: { type: Boolean, default: false }
}, {
  timestamps: true
});

// FIXED: Auto-increment invoiceNumber that considers ALL invoices (including disabled)
invoiceSchema.pre('save', async function(next) {
  if (this.isNew) {
    const today = new Date();
    const day = String(today.getDate()).padStart(2, '0');
    const month = String(today.getMonth() + 1).padStart(2, '0');
    const year = String(today.getFullYear()).slice(-2);
    const datePrefix = `INV-${day}${month}${year}`;
    
    // FIXED: Find ALL invoices with today's date prefix (including disabled)
    const lastInvoice = await this.constructor.findOne({
      invoiceNumber: new RegExp(`^${datePrefix}`)
    }).sort({ invoiceNumber: -1 });
    
    let sequenceNumber = 1;
    if (lastInvoice && lastInvoice.invoiceNumber) {
      const lastSequence = parseInt(lastInvoice.invoiceNumber.split('-')[2]) || 0;
      sequenceNumber = lastSequence + 1;
    }
    
    this.invoiceNumber = `${datePrefix}-${String(sequenceNumber).padStart(2, '0')}`;
  }
  next();
});

export default mongoose.model("Invoice", invoiceSchema);
