import PDFDocument from "pdfkit";
import fs from "fs";
import path from "path";
import Customer from '../models/Customer.js';
import Invoice from '../models/Invoice.js'
import Company from '../models/Company.js';
import pkg from "number-to-words";
 
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
const { toWords } = pkg;
 
// Properly define __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
 
// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, '../uploads/payment-proofs');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
 
// Generate dynamic Invoice PDF - FIXED CURRENCY FOR INR
const getCurrencySymbol = (currency) => {
  const currencySymbols = {
    USD: '$',
    EUR: '€',
    INR: 'Rs. '
  };
  return currencySymbols[currency] || '$';
};
 
// Fixed amount in words function for INR
    const getAmountInWords = (amount, currency) => {
  try {
    const amountInWords = toWords(Math.round(amount));
 
    // Convert to Title Case (Camel-style words)
    const camelCaseWords = amountInWords.replace(/\w\S*/g,
      txt => txt.charAt(0).toUpperCase() + txt.slice(1).toLowerCase()
    );
 
    // Handle different currency names
    if (currency === 'INR') {
      return `${camelCaseWords} Rupees Only`;
    } else if (currency === 'EUR') {
      return `${camelCaseWords} Euros Only`;
    } else {
      return `${camelCaseWords} Dollars Only`;
    }
 
  } catch (error) {
    console.error("Error converting amount to words:", error);
 
    if (currency === 'INR') {
      return `${amount} Rupees Only`;
    } else if (currency === 'EUR') {
      return `${amount} Euros Only`;
    } else {
      return `${amount} Dollars Only`;
    }
  }
};
 
// Format currency amount based on currency type
const formatCurrencyAmount = (amount, currency) => {
  if (currency === 'INR') {
    // Indian numbering system - comma after hundreds, thousands, etc.
    return new Intl.NumberFormat('en-IN', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(amount);
  } else {
    // Western numbering system
    return amount.toFixed(2);
  }
};
 
// Enhanced function to handle payment verification with file upload and storage
export const verifyPayment = async (req, res) => {
  try {
    const { invoiceId, transactionNumber } = req.body;
    const transactionProof = req.file; // Get uploaded file
   
    // Validate required fields
    if (!invoiceId || !transactionNumber) {
      return res.status(400).json({ message: "Invoice ID and transaction number are required" });
    }
 
    if (!transactionProof) {
      return res.status(400).json({ message: "Transaction proof file is required" });
    }
 
    // Validate file type
    const allowedMimeTypes = [
      'application/pdf',
      'image/jpeg',
      'image/jpg',
      'image/png',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
   
    if (!allowedMimeTypes.includes(transactionProof.mimetype)) {
      return res.status(400).json({
        message: "Invalid file type. Supported formats: PDF, JPG, PNG, DOC"
      });
    }
 
    // Validate file size (10MB max)
    if (transactionProof.size > 10 * 1024 * 1024) {
      return res.status(400).json({
        message: "File size too large. Maximum size is 10MB."
      });
    }
 
    // Generate unique filename
    const fileExtension = path.extname(transactionProof.originalname);
    const uniqueFileName = `payment-proof-${invoiceId}-${Date.now()}${fileExtension}`;
    const filePath = path.join(uploadsDir, uniqueFileName);
 
    // Save file to server
    fs.writeFileSync(filePath, transactionProof.buffer);
 
    // Construct file URL
    const fileUrl = `/api/billing/payment-proofs/${uniqueFileName}`;
 
    // Find and update invoice status with file details
    const updatedInvoice = await Invoice.findByIdAndUpdate(
      invoiceId,
      {
        status: "paid",
        $set: {
          "paymentDetails.transactionNumber": transactionNumber,
          "paymentDetails.verifiedAt": new Date(),
          "paymentDetails.proofFile": {
            originalName: transactionProof.originalname,
            mimeType: transactionProof.mimetype,
            size: transactionProof.size,
            uploadedAt: new Date(),
            fileName: uniqueFileName,
            filePath: filePath,
            fileUrl: fileUrl
          }
        }
      },
      { new: true, runValidators: true }
    ).populate("customerId");
 
    if (!updatedInvoice) {
      // Clean up uploaded file if invoice not found
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      return res.status(404).json({ message: "Invoice not found" });
    }
 
    res.json({
      message: "Payment verified successfully",
      invoice: updatedInvoice
    });
 
  } catch (error) {
    console.error("Error verifying payment:", error);
    res.status(500).json({ message: "Error verifying payment", error: error.message });
  }
};
 
// Update existing invoice
export const updateInvoice = async (req, res) => {
  try {
    const { id } = req.params;
    const { customerId, items, invoiceDate, dueDate, taxPercent, notes, currency } = req.body;
 
    console.log('🔄 Updating invoice:', id);
    console.log('📦 Update data:', { customerId, items, invoiceDate, dueDate, taxPercent, notes, currency });
 
    // Validate required fields
    if (!customerId || !items || items.length === 0) {
      return res.status(400).json({ message: "Customer ID and items are required" });
    }
 
    // Fetch customer
    const customer = await Customer.findById(customerId);
    if (!customer) {
      return res.status(404).json({ message: "Customer not found" });
    }
 
    // Calculate totals
    const subtotal = items.reduce((sum, item) => sum + (Number(item.amount) || 0), 0);
    const taxAmount = taxPercent ? (subtotal * taxPercent) / 100 : 0;
    const totalAmount = subtotal + taxAmount;
 
    console.log('💰 Calculated totals:', { subtotal, taxAmount, totalAmount });
 
    // Update invoice in DB
    const updatedInvoice = await Invoice.findByIdAndUpdate(
      id,
      {
        customerId,
        items: items.map(item => ({
          description: item.description,
          remarks: item.remarks || "",
          amount: Number(item.amount) || 0
        })),
        totalAmount,
        date: invoiceDate ? new Date(invoiceDate) : new Date(),
        dueDate: dueDate ? new Date(dueDate) : null,
        taxPercent: taxPercent || 0,
        taxAmount,
        subtotal,
        notes: notes || '',
        currency: currency || "USD"
      },
      { new: true, runValidators: true }
    ).populate("customerId");
 
    if (!updatedInvoice) {
      return res.status(404).json({ message: "Invoice not found" });
    }
 
    console.log('✅ Invoice updated successfully:', updatedInvoice.invoiceNumber);
 
    res.json({
      message: "Invoice updated successfully",
      invoice: updatedInvoice
    });
 
  } catch (error) {
    console.error("❌ Error updating invoice:", error);
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        message: 'Validation error',
        errors: Object.values(error.errors).map(e => e.message)
      });
    }
    res.status(500).json({ message: "Error updating invoice", error: error.message });
  }
};
 
// Serve payment proof files
export const getPaymentProof = async (req, res) => {
  try {
    const { filename } = req.params;
    const filePath = path.join(uploadsDir, filename);
   
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: "File not found" });
    }
 
    // Set appropriate headers based on file type
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes = {
      '.pdf': 'application/pdf',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.doc': 'application/msword',
      '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    };
 
    const mimeType = mimeTypes[ext] || 'application/octet-stream';
   
    // For images and PDFs, display in browser; for others, download
    if (['.pdf', '.jpg', '.jpeg', '.png'].includes(ext)) {
      res.setHeader('Content-Type', mimeType);
      res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    } else {
      res.setHeader('Content-Type', mimeType);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    }
 
    // Stream the file
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
 
  } catch (error) {
    console.error("Error serving payment proof:", error);
    res.status(500).json({ message: "Error serving file" });
  }
};
 
// Get payment proof info for a specific invoice
export const getInvoicePaymentProof = async (req, res) => {
  try {
    const { id } = req.params;
   
    const invoice = await Invoice.findById(id);
    if (!invoice) {
      return res.status(404).json({ message: "Invoice not found" });
    }
 
    if (!invoice.paymentDetails?.proofFile) {
      return res.status(404).json({ message: "No payment proof found for this invoice" });
    }
 
    res.json({
      paymentProof: invoice.paymentDetails.proofFile
    });
 
  } catch (error) {
    console.error("Error fetching payment proof:", error);
    res.status(500).json({ message: "Error fetching payment proof", error: error.message });
  }
};
 
// Add this function to delete invoice
export const deleteInvoice = async (req, res) => {
  try {
    const { id } = req.params;
   
    const invoice = await Invoice.findById(id);
    if (!invoice) {
      return res.status(404).json({ message: "Invoice not found" });
    }
 
    // Delete associated payment proof file if exists
    if (invoice.paymentDetails?.proofFile?.filePath) {
      try {
        if (fs.existsSync(invoice.paymentDetails.proofFile.filePath)) {
          fs.unlinkSync(invoice.paymentDetails.proofFile.filePath);
        }
      } catch (fileError) {
        console.error("Error deleting payment proof file:", fileError);
      }
    }
 
    const deletedInvoice = await Invoice.findByIdAndDelete(id);
   
    res.json({ message: "Invoice deleted successfully" });
   
  } catch (error) {
    console.error("Error deleting invoice:", error);
    res.status(500).json({ message: "Error deleting invoice", error: error.message });
  }
};
 
// Update the generateInvoice function
export const generateInvoice = async (req, res) => {
  try {
    const { customerId, items, totalAmount, invoiceDate, dueDate, taxPercent, notes, currency } = req.body;
 
    // Validate required fields
    if (!customerId || !items || items.length === 0) {
      return res.status(400).json({ message: "Customer ID and items are required" });
    }
 
    // Fetch customer
    const customer = await Customer.findById(customerId);
    if (!customer) {
      return res.status(404).json({ message: "Customer not found" });
    }
 
    // Fetch or create company info
    let company = await Company.findOne();
    if (!company) {
      // Create default company info if none exists
      company = await Company.create({
        companyName: 'Zynith IT Solutions',
        address: '123 Business Street, City, State 12345',
        phone: '+1 (555) 123-4567',
        email: 'contact@zynith-it.com',
        taxId: 'TAX-123456789',
      });
    }
 
    // Calculate totals
    const subtotal = items.reduce((sum, item) => sum + (Number(item.amount) || 0), 0);
    const taxAmount = taxPercent ? (subtotal * taxPercent) / 100 : 0;
    const grandTotal = subtotal + taxAmount;
 
    // Save invoice in DB with currency and remarks - UPDATED TO INCLUDE REMARKS
    const invoice = new Invoice({
      customerId,
      items: items.map(item => ({
        description: item.description,
        remarks: item.remarks || "", // ADD REMARKS FIELD
        amount: Number(item.amount) || 0
      })),
      totalAmount: grandTotal,
      date: invoiceDate ? new Date(invoiceDate) : new Date(),
      dueDate: dueDate ? new Date(dueDate) : null,
      taxPercent: taxPercent || 0,
      taxAmount,
      subtotal,
      notes,
      currency: currency || "USD",
      status: "sent"
    });
    await invoice.save();
 
    // Fetch the saved invoice to get the auto-generated numbers
    const savedInvoice = await Invoice.findById(invoice._id).populate("customerId");
 
    // PDF setup - stream directly to response
    const doc = new PDFDocument({
      size: "A4",
      margin: 50,
      bufferPages: true
    });
   
    // Set response headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=${savedInvoice.invoiceNumber}.pdf`);
   
    doc.pipe(res);
 
    // ===== DYNAMIC POSITIONING VARIABLES =====
    let currentY = 30;
    const leftColumn = 50;
    const rightColumn = 350;
    const pageWidth = 550;
    const columnWidth = 200;
 
    // Get currency symbol and name
    const currencySymbol = getCurrencySymbol(currency);
    const amountWords = getAmountInWords(grandTotal, currency);
 
    // ===== LOGO SECTION =====
      const addHeader = (pageNumber) => {
      const headerY = 30;
     
      // ===== LOGO SECTION =====
      const logoWidth = 140;
      const logoHeight = 100;
      const logoX = pageWidth - logoWidth + 15;
     
      try {
        const logoPath = join(__dirname, 'logo.png');
        if (fs.existsSync(logoPath)) {
          doc.image(logoPath, logoX, 20, {
            width: logoWidth,
            height: logoHeight
          });
        }
      } catch (logoError) {
        console.error("❌ Error loading logo:", logoError);
      }
 
      // ===== COMPANY INFO =====
    //   doc.fontSize(20).font('Helvetica-Bold').text(company.companyName, leftColumn, headerY);
     
    //   doc.fontSize(10).font('Helvetica')
    //      .text(company.address, leftColumn, headerY + 30)
    //      .text(`Phone: ${company.phone || "000-000-0000"}`, leftColumn, headerY + 45)
    //      .text(`Email: ${company.email || "contact@company.com"}`, leftColumn, headerY + 60);
 
    //   if (company.taxId) {
    //     doc.text(`TaxID: ${company.taxId}`, leftColumn, headerY + 75);
    //   }
 
    //   // Horizontal line after header
    //   const lineY = Math.max(headerY + logoHeight, headerY + 90) + 10;
    //   doc.moveTo(leftColumn, lineY).lineTo(pageWidth, lineY).stroke();
     
    //   // ADD SPACE AFTER HEADER LINE - This is the key change
    //   const spaceAfterHeader = 20; // Adjust this value to increase/decrease space
     
    //   // Page number (optional)
    //   // doc.fontSize(8).font('Helvetica')
    //   //    .text(`Page ${pageNumber}`, pageWidth - 30, headerY + 10);
     
    //   // Return the Y position after header (line position + space)
    //   return lineY + spaceAfterHeader;
    // };
 
 
      // ===== COMPANY INFO =====
  // Company Name
  doc.fontSize(20).font('Helvetica-Bold')
     .text(company.companyName, leftColumn, headerY);
 
  // Set font and line height for company details
  doc.fontSize(10).font('Helvetica');
  const lineSpacing = 2; // uniform spacing between lines
 
  // Start Y position for address and details
  let currentY = headerY + 30;
 
  // Draw address with wrapping and get its bottom position
  const addressText = company.address || "123 Main Street, City, ZIP";
  const addressWidth = pageWidth / 2; // keep it within half the page width
  const addressHeight = doc.heightOfString(addressText, {
    width: addressWidth,
  });
 
  doc.text(addressText, leftColumn, currentY, { width: addressWidth });
  currentY += addressHeight + lineSpacing;
 
  // Draw phone number
  doc.text(`Phone: ${company.phone || "000-000-0000"}`, leftColumn, currentY);
  currentY += doc.heightOfString("A", { width: addressWidth }) + lineSpacing;
 
  // Draw email
  doc.text(`Email: ${company.email || "contact@company.com"}`, leftColumn, currentY);
  currentY += doc.heightOfString("A", { width: addressWidth }) + lineSpacing;
 
  // Horizontal line after header (whichever is lower — logo or text)
  const lineY = Math.max(headerY + logoHeight, currentY) + 10;
  doc.moveTo(leftColumn, lineY).lineTo(pageWidth, lineY).stroke();
 
  // Add space after header
  const spaceAfterHeader = 20;
 
  // Return Y position after header (line + space)
  return lineY + spaceAfterHeader;
}
///--------------------------Company Infor----------------------------------------------------------------------
 
     // ===== FOOTER LINE FUNCTION - FOR EVERY PAGE =====
    const addFooterLine = () => {
      const footerY = 750;
      doc.moveTo(leftColumn, footerY).lineTo(pageWidth, footerY).stroke();
    };
 
    // ===== FINAL FOOTER FUNCTION - FOR LAST PAGE ONLY =====
    const addFinalFooter = () => {
      const footerY = 750;
      doc.moveTo(leftColumn, footerY).lineTo(pageWidth, footerY).stroke();
      doc.fontSize(14).font('Helvetica')
         .text("Thank You For Your Business!", (leftColumn + pageWidth) / 2, footerY + 15, { align: "right" });
    };
 
    // ===== TABLE HEADER FUNCTION =====
    const addTableHeader = (yPosition) => {
      doc.rect(leftColumn, yPosition, pageWidth - leftColumn, 20).fill("#f0f0f0");
      doc.fontSize(10).font('Helvetica-Bold').fillColor("#000")
         .text("DESCRIPTION", leftColumn + 10, yPosition + 5)
         .text("REMARKS", leftColumn + 200, yPosition + 5)
         .text(`AMOUNT (${currencySymbol})`, pageWidth - 80, yPosition + 5, { align: "right" });
    };
 
    // ===== TRACK PAGES FOR HEADER/FOOTER =====
    let pageNumber = 1;
   
    // Add header to first page and get the starting Y position
    currentY = addHeader(pageNumber);
   
    // Listen for page additions to add headers to subsequent pages
    doc.on('pageAdded', () => {
      pageNumber++;
      currentY = addHeader(pageNumber); // Reset currentY for new page
      addFooterLine(); // Add footer line to every new page
    });
 
    // Add footer line to first page
    addFooterLine();
 
    // ===== BILL TO SECTION - LEFT SIDE =====
  // ===== BILL TO SECTION - LEFT SIDE =====
const billToStartY = currentY;
doc.fontSize(16).font('Helvetica-Bold').text("BILL TO", leftColumn, currentY);
currentY += 25; // Spacing after "BILL TO" title
 
// Skip customer name and use company directly
const customerCompany = customer.company;
 
if (customerCompany) {
  doc.fontSize(10).font('Helvetica-Bold')
     .text(customerCompany, leftColumn, currentY);
  currentY += 20; // 3 spaces after company name
}
 
// Handle multi-line address with consistent spacing
const addressLines = customer.address.split('\n').filter(line => line.trim() !== '');
addressLines.forEach((line, index) => {
  doc.fontSize(10).font('Helvetica')
     .text(line.trim(), leftColumn, currentY);
  currentY += 15; // 2 spaces for each address line
});
 
// Add phone and email with consistent spacing
if (customer.phone) {
  doc.text(`Phone: ${customer.phone}`, leftColumn, currentY);
  currentY += 15; // 2 spaces
}
 
if (customer.email) {
  doc.text(`Email: ${customer.email}`, leftColumn, currentY);
  currentY += 15; // 2 spaces
}
 
// Reset currentY to the highest point for right column to maintain layout
currentY = billToStartY;
 
 
///---------------------------- Bill To ---generate -------------------------------------------------------------------------
 
 
 
    // ===== INVOICE DETAILS SECTION - RIGHT SIDE =====
    doc.fontSize(16).font('Helvetica-Bold').text("INVOICE", rightColumn, currentY);
    currentY += 25;
 
    // Invoice details in two columns
    const detailLabels = ["DATE                 :", "INVOICE NO     :", "CUSTOMER ID :", "DUE DATE        :"];
    const invDate = new Date(savedInvoice.date).toISOString().split('T')[0];
    const due = savedInvoice.dueDate ? new Date(savedInvoice.dueDate).toISOString().split('T')[0] : 'N/A';
    const detailValues = [
      invDate,
      savedInvoice.invoiceNumber, // Use auto-generated invoice number
      savedInvoice.customerId.customerId, // Use auto-generated customer ID
      due
    ];
 
    detailLabels.forEach((label, index) => {
      doc.fontSize(10).font('Helvetica-Bold')
         .text(label, rightColumn, currentY);
      doc.font('Helvetica')
         .text(detailValues[index], rightColumn + 80, currentY);
      currentY += 15;
    });
 
    // ===== ITEMS TABLE =====
    const leftColumnBottom = billToStartY + 120;
    currentY = Math.max(currentY, leftColumnBottom) + 10;
 
    // Add table header
    addTableHeader(currentY);
    currentY += 25;
 
    // Table rows
    items.forEach((item, index) => {
      // Check if we need a new page
      if (currentY > 650) {
        doc.addPage();
        currentY = 150; // Reset Y position after header on new page
        // Add table header on new page
        addTableHeader(currentY);
        currentY += 25;
      }
 
      // Alternate row background
      const remarks = item.remarks || "";
     
      // Calculate heights for both columns
      const descriptionHeight = doc.heightOfString(item.description, {
        width: 180,
        align: 'left'
      });
     
      const remarksHeight = doc.heightOfString(remarks, {
        width: 150,
        align: 'left'
      });
      const formattedAmount = formatCurrencyAmount(Number(item.amount), currency);
      // Use the maximum height for the row
      const rowHeight = Math.max(descriptionHeight, remarksHeight, 20);
 
      // Draw background for entire row
      if (index % 2 === 0) {
        doc.rect(leftColumn, currentY - 5, pageWidth - leftColumn, rowHeight + 10)
           .fillOpacity(0.1).fill("#eeeeee").fillOpacity(1).fillColor('black');
      }
 
      // Draw description
      doc.fontSize(10).font('Helvetica')
         .text(item.description, leftColumn + 10, currentY, {
           width: 180,
           align: 'left'
         });
 
      // Draw remarks
      doc.text(remarks, leftColumn + 200, currentY, {
        width: 150,
        align: 'left'
      });
 
      // Draw amount
      doc.text(`${currencySymbol}${formattedAmount}`, pageWidth - 100, currentY, {
        align: "right"
      });
     
      currentY += rowHeight + 10;
    });
 
    // ===== TOTALS SECTION =====
    currentY += 10;
    // Format amounts based on currency
    const formattedSubtotal = formatCurrencyAmount(subtotal, currency);
    const formattedTaxAmount = formatCurrencyAmount(taxAmount, currency);
    const formattedGrandTotal = formatCurrencyAmount(grandTotal, currency);
   
    // Subtotal
    doc.fontSize(10).font('Helvetica')
       .text("Subtotal:", pageWidth - 150, currentY, { align: "left" })
       .text(`${currencySymbol}${formattedSubtotal}`, pageWidth - 100, currentY, { align: "right" });
    currentY += 20;
   
    // Tax
    if (taxPercent > 0) {
      doc.text(`Tax (${taxPercent}%):`, pageWidth - 150, currentY, { align: "left" })
         .text(`${currencySymbol}${formattedTaxAmount}`, pageWidth - 100, currentY, { align: "right" });
      currentY += 20;
    }
   
    // Total
    doc.moveTo(pageWidth - 200, currentY).lineTo(pageWidth, currentY).stroke();
    currentY += 15;
   
    doc.fontSize(12).font('Helvetica-Bold')
       .text("TOTAL:", pageWidth - 150, currentY, { align: "left" })
       .text(`${currencySymbol}${formattedGrandTotal}`, pageWidth - 100, currentY, { align: "right" });
    currentY += 20;
 
    doc.moveTo(pageWidth - 200, currentY).lineTo(pageWidth, currentY).stroke();
    currentY += 20;
 
    // ===== AMOUNT IN WORDS =====
    //const amountWords = toWords(Math.round(grandTotal)) + " dollars only";
    const wordsHeight = doc.heightOfString(amountWords + "/- .", { width: pageWidth - leftColumn });
   
    doc.fontSize(10).font('Helvetica-Bold')
       .text(`Amount in Words: ${amountWords}`, leftColumn, currentY, {
         width: pageWidth - leftColumn
       });
    currentY += wordsHeight + 20;
 
    // ===== OTHER COMMENTS SECTION =====
 
    // doc.fontSize(11).font('Helvetica-Bold').text("OTHER COMMENTS", leftColumn, currentY);
    // currentY += 15;
 
    // // Add Additional Notes from the form (if provided)
    // if (notes && notes.trim() !== "") {
    //   doc.fontSize(10).font('Helvetica')
    //      .text(`${'•'} ${notes}`, leftColumn + 10, currentY);
    //   currentY += 30;
    // }
 
    if (invoice.notes && invoice.notes.trim() !== "") {
    doc.fontSize(11).font('Helvetica-Bold').text("OTHER COMMENTS", leftColumn, currentY);
    currentY += 15;
 
    // Add Additional Notes from the form (if provided)
   
      // Split notes by '.' to create bullet points for each sentence
      const sentences = invoice.notes.split('.').map(s => s.trim()).filter(s => s.length > 0);
 
      doc.fontSize(10).font('Helvetica');
      sentences.forEach(sentence => {
        const bulletText = `• ${sentence}.`;
        const textHeight = doc.heightOfString(bulletText, { width: 500 }); // wrap text properly
        doc.text(bulletText, leftColumn + 10, currentY, { width: 500 });
        currentY += textHeight + 5; // move down for next bullet
      });
    }
 
    // Terms & Conditions section
    doc.fontSize(10).font('Helvetica-Bold').text("Terms & Conditions", leftColumn, currentY);
    currentY += 15;
 
    const defaultComments = [
      "Total payment due in 30 days",
      "Please include the invoice number on your check"
    ];
 
    // Add default comments with bullet points
    defaultComments.forEach((comment, index) => {
      doc.fontSize(10).font('Helvetica')
         .text(`${'•'} ${comment}`, leftColumn + 10, currentY);
      currentY += 15;
    });
 
    // ===== SIGNATURE SECTION =====
    const signatureY = 680;
    const signatureX = pageWidth - 125;
   
    doc.fontSize(11).font('Helvetica')
       .text('For Zynith IT Solutions', signatureX - 40, signatureY + 5, {
         width: 150,
         align: 'center'
       });
 
    // ===== ADD FINAL FOOTER TO LAST PAGE =====
    addFinalFooter();
 
    doc.end();
 
  } catch (error) {
    console.error("Error generating invoice:", error);
    res.status(500).json({ message: "Error generating invoice", error: error.message });
  }
};
 
// Update the downloadInvoice function to use the same design as generateInvoice
export const downloadInvoice = async (req, res) => {
  try {
    console.log('📥 Download invoice request received for ID:', req.params.id);
    const { id } = req.params;
   
    if (!id) {
      return res.status(400).json({ message: "Invoice ID is required" });
    }
 
    // Fetch invoice with customer details
    const invoice = await Invoice.findById(id).populate("customerId");
 
    if (!invoice) {
      return res.status(404).json({ message: "Invoice not found" });
    }
 
    // Fetch or create company info
    let company = await Company.findOne();
   
    if (!company) {
      company = {
        companyName: 'Zynith IT Solutions',
        address: '123 Business Street, City, State 12345',
        phone: '+1 (555) 123-4567',
        email: 'contact@zynith-it.com',
        taxId: 'TAX-123456789',
      };
    }
 
    // PDF setup - stream directly to response
    const doc = new PDFDocument({
      size: "A4",
      margin: 50,
      bufferPages: true
    });
   
    // Set response headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=${invoice.invoiceNumber}.pdf`);
    res.setHeader('X-Invoice-Number', invoice.invoiceNumber); // Add this line
   
    doc.pipe(res);
 
    // ===== DYNAMIC POSITIONING VARIABLES =====
    let currentY = 30;
    const leftColumn = 50;
    const rightColumn = 350;
    const pageWidth = 550;
    const columnWidth = 200;
 
    // Get currency symbol and name
    const currencySymbol = getCurrencySymbol(invoice.currency);
    const amountWords = getAmountInWords(invoice.totalAmount, invoice.currency);
 
    // ===== LOGO SECTION =====
    const addHeader = (pageNumber) => {
      const headerY = 30;
     
      // ===== LOGO SECTION =====
      const logoWidth = 140;
      const logoHeight = 100;
      const logoX = pageWidth - logoWidth + 15;
     
      try {
        const logoPath = join(__dirname, 'logo.png');
        if (fs.existsSync(logoPath)) {
          doc.image(logoPath, logoX, 20, {
            width: logoWidth,
            height: logoHeight
          });
        }
      } catch (logoError) {
        console.error("❌ Error loading logo:", logoError);
      }
 
      // ===== COMPANY INFO =====
    //   doc.fontSize(20).font('Helvetica-Bold').text(company.companyName, leftColumn, headerY);
     
    //   doc.fontSize(10).font('Helvetica')
    //      .text(company.address, leftColumn, headerY + 30)
    //      .text(`Phone: ${company.phone || "000-000-0000"}`, leftColumn, headerY + 45)
    //      .text(`Email: ${company.email || "contact@company.com"}`, leftColumn, headerY + 60);
 
    //   // Horizontal line after header
    //   const lineY = Math.max(headerY + logoHeight, headerY + 90) + 10;
    //   doc.moveTo(leftColumn, lineY).lineTo(pageWidth, lineY).stroke();
     
    //   // ADD SPACE AFTER HEADER LINE
    //   const spaceAfterHeader = 20;
     
    //   // Return the Y position after header (line position + space)
    //   return lineY + spaceAfterHeader;
    // };
 
 
 
        // ===== COMPANY INFO =====
  // Company Name
  doc.fontSize(20).font('Helvetica-Bold')
     .text(company.companyName, leftColumn, headerY);
 
  // Set font and line height for company details
  doc.fontSize(10).font('Helvetica');
  const lineSpacing = 2; // uniform spacing between lines
 
  // Start Y position for address and details
  let currentY = headerY + 30;
 
  // Draw address with wrapping and get its bottom position
  const addressText = company.address || "123 Main Street, City, ZIP";
  const addressWidth = pageWidth / 2; // keep it within half the page width
  const addressHeight = doc.heightOfString(addressText, {
    width: addressWidth,
  });
 
  doc.text(addressText, leftColumn, currentY, { width: addressWidth });
  currentY += addressHeight + lineSpacing;
 
  // Draw phone number
  doc.text(`Phone: ${company.phone || "000-000-0000"}`, leftColumn, currentY);
  currentY += doc.heightOfString("A", { width: addressWidth }) + lineSpacing;
 
  // Draw email
  doc.text(`Email: ${company.email || "contact@company.com"}`, leftColumn, currentY);
  currentY += doc.heightOfString("A", { width: addressWidth }) + lineSpacing;
 
  // Horizontal line after header (whichever is lower — logo or text)
  const lineY = Math.max(headerY + logoHeight, currentY) + 10;
  doc.moveTo(leftColumn, lineY).lineTo(pageWidth, lineY).stroke();
 
  // Add space after header
  const spaceAfterHeader = 20;
 
  // Return Y position after header (line + space)
  return lineY + spaceAfterHeader;
}
     // ===== FOOTER LINE FUNCTION - FOR EVERY PAGE =====
    const addFooterLine = () => {
      const footerY = 750;
      doc.moveTo(leftColumn, footerY).lineTo(pageWidth, footerY).stroke();
    };
 
    // ===== FINAL FOOTER FUNCTION - FOR LAST PAGE ONLY =====
    const addFinalFooter = () => {
      const footerY = 750;
      doc.moveTo(leftColumn, footerY).lineTo(pageWidth, footerY).stroke();
      doc.fontSize(14).font('Helvetica')
         .text("Thank You For Your Business!", (leftColumn + pageWidth) / 2, footerY + 15, { align: "right" });
    };
 
    // ===== TABLE HEADER FUNCTION =====
    const addTableHeader = (yPosition) => {
      doc.rect(leftColumn, yPosition, pageWidth - leftColumn, 20).fill("#f0f0f0");
      doc.fontSize(10).font('Helvetica-Bold').fillColor("#000")
         .text("DESCRIPTION", leftColumn + 10, yPosition + 5)
         .text("REMARKS", leftColumn + 200, yPosition + 5)
         .text(`AMOUNT (${currencySymbol})`, pageWidth - 80, yPosition + 5, { align: "right" });
    };
 
    // ===== TRACK PAGES FOR HEADER/FOOTER =====
    let pageNumber = 1;
   
    // Add header to first page and get the starting Y position
    currentY = addHeader(pageNumber);
   
    // Listen for page additions to add headers to subsequent pages
    doc.on('pageAdded', () => {
      pageNumber++;
      currentY = addHeader(pageNumber); // Reset currentY for new page
      addFooterLine(); // Add footer line to every new page
    });
 
    // Add footer line to first page
    addFooterLine();
 
    // // ===== BILL TO SECTION - LEFT SIDE =====
    // const billToStartY = currentY;
    // doc.fontSize(16).font('Helvetica-Bold').text("BILL TO", leftColumn, currentY);
    // currentY += 20;
 
    // doc.fontSize(10).font('Helvetica')
    //    .text(invoice.customerId.name, leftColumn, currentY);
    // currentY += 15;
   
    // if (invoice.customerId.company) {
    //   doc.text(invoice.customerId.company, leftColumn, currentY);
    //   currentY += 15;
    // }
   
    // // Handle multi-line address
    // const addressLines = doc.heightOfString(invoice.customerId.address, { width: columnWidth });
    // doc.text(invoice.customerId.address, leftColumn, currentY, { width: columnWidth });
    // currentY += addressLines + 5;
   
    // doc.text(`Phone: ${invoice.customerId.phone}`, leftColumn, currentY);
    // currentY += 15;
   
    // doc.text(`Email: ${invoice.customerId.email}`, leftColumn, currentY);
   
    // // Reset currentY to the highest point for right column
    // currentY = billToStartY;
   
 
        // ===== BILL TO SECTION - LEFT SIDE =====
    const billToStartY = currentY;
    doc.fontSize(16).font('Helvetica-Bold').text("BILL TO", leftColumn, currentY);
    currentY += 25; // Spacing after "BILL TO" title
 
    // Skip customer name and use company directly - USE CORRECT FIELD NAME
    const customerCompany = invoice.customerId.company;
 
    if (customerCompany) {
      doc.fontSize(10).font('Helvetica-Bold')
         .text(customerCompany, leftColumn, currentY);
      currentY += 20; // 3 spaces after company name
    }
 
    // Handle multi-line address with consistent spacing - USE CORRECT FIELD NAME
    const addressLines = invoice.customerId.address.split('\n').filter(line => line.trim() !== '');
    addressLines.forEach((line, index) => {
      doc.fontSize(10).font('Helvetica')
         .text(line.trim(), leftColumn, currentY);
      currentY += 15; // 2 spaces for each address line
    });
 
    // Add phone and email with consistent spacing - USE CORRECT FIELD NAMES
    if (invoice.customerId.phone) {
      doc.text(`Phone: ${invoice.customerId.phone}`, leftColumn, currentY);
      currentY += 15; // 2 spaces
    }
 
    if (invoice.customerId.email) {
      doc.text(`Email: ${invoice.customerId.email}`, leftColumn, currentY);
      currentY += 15; // 2 spaces
    }
 
    // Reset currentY to the highest point for right column to maintain layout
    currentY = billToStartY;
//-----------------------------------------------------------------bill to download ------------------------------------------------
    // ===== INVOICE DETAILS SECTION - RIGHT SIDE =====
    doc.fontSize(16).font('Helvetica-Bold').text("INVOICE", rightColumn, currentY);
    currentY += 25;
 
    // Invoice details in two columns
    const detailLabels = ["DATE                 :", "INVOICE NO     :", "CUSTOMER ID :", "DUE DATE        :"];
    const invDate = new Date(invoice.date).toISOString().split('T')[0];
    const due = invoice.dueDate ? new Date(invoice.dueDate).toISOString().split('T')[0] : 'N/A';
    const detailValues = [
      invDate,
      invoice.invoiceNumber, // Use auto-generated invoice number
      invoice.customerId.customerId, // Use auto-generated customer ID
      due
    ];
 
    detailLabels.forEach((label, index) => {
      doc.fontSize(10).font('Helvetica-Bold')
         .text(label, rightColumn, currentY);
      doc.font('Helvetica')
         .text(detailValues[index], rightColumn + 80, currentY);
      currentY += 15;
    });
 
    // ===== ITEMS TABLE =====
    const leftColumnBottom = billToStartY + 120;
    currentY = Math.max(currentY, leftColumnBottom) + 10;
 
    // Add table header
    addTableHeader(currentY);
    currentY += 25;
 
    // Table rows - USE ACTUAL INVOICE ITEMS
    invoice.items.forEach((item, index) => {
      // Check if we need a new page
      if (currentY > 650) {
        doc.addPage();
        currentY = 150; // Reset Y position after header on new page
        // Add table header on new page
        addTableHeader(currentY);
        currentY += 25;
      }
 
      // Use actual remarks from item or fallback
      const remarks = item.remarks || "";
     
      // Calculate heights for both columns
      const descriptionHeight = doc.heightOfString(item.description, {
        width: 180,
        align: 'left'
      });
     
      const remarksHeight = doc.heightOfString(remarks, {
        width: 150,
        align: 'left'
      });
     
      const formattedAmount = formatCurrencyAmount(Number(item.amount), invoice.currency);
      // Use the maximum height for the row
      const rowHeight = Math.max(descriptionHeight, remarksHeight, 20);
 
      // Draw background for entire row
      if (index % 2 === 0) {
        doc.rect(leftColumn, currentY - 5, pageWidth - leftColumn, rowHeight + 10)
           .fillOpacity(0.1).fill("#eeeeee").fillOpacity(1).fillColor('black');
      }
 
      // Draw description
      doc.fontSize(10).font('Helvetica')
         .text(item.description, leftColumn + 10, currentY, {
           width: 180,
           align: 'left'
         });
 
      // Draw remarks
      doc.text(remarks, leftColumn + 200, currentY, {
        width: 150,
        align: 'left'
      });
 
      // Draw amount
      doc.text(`${currencySymbol}${formattedAmount}`, pageWidth - 100, currentY, {
        align: "right"
      });
     
      currentY += rowHeight + 10;
    });
 
    // ===== TOTALS SECTION =====
    currentY += 10;
    // Format amounts based on currency
    const formattedSubtotal = formatCurrencyAmount(invoice.subtotal, invoice.currency);
    const formattedTaxAmount = formatCurrencyAmount(invoice.taxAmount, invoice.currency);
    const formattedGrandTotal = formatCurrencyAmount(invoice.totalAmount, invoice.currency);
   
    // Subtotal
    doc.fontSize(10).font('Helvetica')
       .text("Subtotal:", pageWidth - 150, currentY, { align: "left" })
       .text(`${currencySymbol}${formattedSubtotal}`, pageWidth - 100, currentY, { align: "right" });
    currentY += 20;
   
    // Tax
    if (invoice.taxPercent > 0) {
      doc.text(`Tax (${invoice.taxPercent}%):`, pageWidth - 150, currentY, { align: "left" })
         .text(`${currencySymbol}${formattedTaxAmount}`, pageWidth - 100, currentY, { align: "right" });
      currentY += 20;
    }
   
    // Total
    doc.moveTo(pageWidth - 200, currentY).lineTo(pageWidth, currentY).stroke();
    currentY += 15;
   
    doc.fontSize(12).font('Helvetica-Bold')
       .text("TOTAL:", pageWidth - 150, currentY, { align: "left" })
       .text(`${currencySymbol}${formattedGrandTotal}`, pageWidth - 100, currentY, { align: "right" });
    currentY += 20;
 
    doc.moveTo(pageWidth - 200, currentY).lineTo(pageWidth, currentY).stroke();
    currentY += 20;
 
    // ===== AMOUNT IN WORDS =====
    const wordsHeight = doc.heightOfString(amountWords + "/- .", { width: pageWidth - leftColumn });
   
    doc.fontSize(10).font('Helvetica-Bold')
       .text(`Amount in Words: ${amountWords}`, leftColumn, currentY, {
         width: pageWidth - leftColumn
       });
    currentY += wordsHeight + 20;
 
    // ===== OTHER COMMENTS SECTION =====
    if (invoice.notes && invoice.notes.trim() !== "") {
    doc.fontSize(11).font('Helvetica-Bold').text("OTHER COMMENTS", leftColumn, currentY);
    currentY += 15;
 
    // Add Additional Notes from the form (if provided)
   
      // Split notes by '.' to create bullet points for each sentence
      const sentences = invoice.notes.split('.').map(s => s.trim()).filter(s => s.length > 0);
 
      doc.fontSize(10).font('Helvetica');
      sentences.forEach(sentence => {
        const bulletText = `• ${sentence}.`;
        const textHeight = doc.heightOfString(bulletText, { width: 500 }); // wrap text properly
        doc.text(bulletText, leftColumn + 10, currentY, { width: 500 });
        currentY += textHeight + 5; // move down for next bullet
      });
    }
 
    // Terms & Conditions section
    doc.fontSize(10).font('Helvetica-Bold').text("Terms & Conditions", leftColumn, currentY);
    currentY += 15;
 
    const defaultComments = [
      "Total payment due in 30 days",
      "Please include the invoice number on your check"
    ];
 
    // Add default comments with bullet points
    defaultComments.forEach((comment, index) => {
      doc.fontSize(10).font('Helvetica')
         .text(`${'•'} ${comment}`, leftColumn + 10, currentY);
      currentY += 15;
    });
 
    // ===== SIGNATURE SECTION =====
    // ===== SIGNATURE SECTION =====
    const signatureY = 680;
    const signatureX = pageWidth - 125;
    const logoWidth = 100;
    const logoHeight = 50;
    try {
        const slogoPath = join(__dirname, 'Sign.png');
        if (fs.existsSync(slogoPath)) {
          doc.image(slogoPath, signatureX-20,signatureY-55, {
            width: logoWidth,
            height: logoHeight
          });
        }
      } catch (logoError) {
        console.error("❌ Error loading logo:", logoError);
      }
   
    doc.fontSize(10).font('Helvetica')
       .text('For Zynith IT Solutions', signatureX - 40, signatureY + 5, {
         width: 150,
         align: 'center'
       });
 
    // ===== ADD FINAL FOOTER TO LAST PAGE =====
    addFinalFooter();
 
    doc.end();
 
    console.log('✅ PDF generated successfully');
 
  } catch (error) {
    console.error("❌ Error downloading invoice:", error);
    console.error("❌ Error stack:", error.stack);
    res.status(500).json({
      message: "Error downloading invoice",
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};
 
// Get all invoices
export const getInvoices = async (req, res) => {
  try {
    const invoices = await Invoice.find()
      .populate("customerId", "name email phone")
      .sort({ date: -1 });
    res.json(invoices);
  } catch (error) {
    console.error("Error fetching invoices:", error);
    res.status(500).json({ message: "Error fetching invoices", error: error.message });
  }
};
 
// Get active invoices (non-disabled)
export const getActiveInvoices = async (req, res) => {
  try {
    const invoices = await Invoice.find({ isDisabled: false })
      .populate("customerId", "name email phone")
      .sort({ date: -1 });
    res.json(invoices);
  } catch (error) {
    console.error("Error fetching active invoices:", error);
    res.status(500).json({ message: "Error fetching invoices", error: error.message });
  }
};
 
// Get disabled invoices
export const getDisabledInvoices = async (req, res) => {
  try {
    const invoices = await Invoice.find({ isDisabled: true })
      .populate("customerId", "name email phone")
      .sort({ date: -1 });
    res.json(invoices);
  } catch (error) {
    console.error("Error fetching disabled invoices:", error);
    res.status(500).json({ message: "Error fetching disabled invoices", error: error.message });
  }
};
 
// Get invoice by ID
export const getInvoiceById = async (req, res) => {
  try {
    const invoice = await Invoice.findById(req.params.id)
      .populate("customerId");
   
    if (!invoice) {
      return res.status(404).json({ message: "Invoice not found" });
    }
    res.json(invoice);
  } catch (error) {
    console.error("Error fetching invoice:", error);
    res.status(500).json({ message: "Error fetching invoice", error: error.message });
  }
};
 
// Disable invoice (soft delete)
export const disableInvoice = async (req, res) => {
  try {
    const { id } = req.params;
   
    const invoice = await Invoice.findByIdAndUpdate(
      id,
      {
        isDisabled: true,
        deleted: true
      },
      { new: true }
    ).populate("customerId");
 
    if (!invoice) {
      return res.status(404).json({ message: "Invoice not found" });
    }
 
    res.json({
      message: "Invoice moved to disabled invoices successfully",
      invoice
    });
  } catch (error) {
    console.error("Error disabling invoice:", error);
    res.status(500).json({ message: "Error disabling invoice", error: error.message });
  }
};
 
// Restore disabled invoice
export const restoreInvoice = async (req, res) => {
  try {
    const { id } = req.params;
   
    const invoice = await Invoice.findByIdAndUpdate(
      id,
      {
        isDisabled: false,
        deleted: false
      },
      { new: true }
    ).populate("customerId");
 
    if (!invoice) {
      return res.status(404).json({ message: "Invoice not found" });
    }
 
    res.json({
      message: "Invoice restored successfully",
      invoice
    });
  } catch (error) {
    console.error("Error restoring invoice:", error);
    res.status(500).json({ message: "Error restoring invoice", error: error.message });
  }
};
 
// Permanently delete invoice
export const permanentDeleteInvoice = async (req, res) => {
  try {
    const { id } = req.params;
   
    const invoice = await Invoice.findOne({ _id: id, isDisabled: true });
    if (!invoice) {
      return res.status(404).json({ message: "Disabled invoice not found" });
    }
 
    // Delete associated payment proof file if exists
    if (invoice.paymentDetails?.proofFile?.filePath) {
      try {
        if (fs.existsSync(invoice.paymentDetails.proofFile.filePath)) {
          fs.unlinkSync(invoice.paymentDetails.proofFile.filePath);
        }
      } catch (fileError) {
        console.error("Error deleting payment proof file:", fileError);
      }
    }
 
    await Invoice.findByIdAndDelete(id);
   
    res.json({ message: "Invoice permanently deleted successfully" });
  } catch (error) {
    console.error("Error permanently deleting invoice:", error);
    res.status(500).json({ message: "Error deleting invoice", error: error.message });
  }
};
 