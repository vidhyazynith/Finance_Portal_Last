import mongoose from "mongoose";
import Counter from "./Counter.js";
 
const customerSchema = new mongoose.Schema({
  customerId: { type: String, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  address: { type: String, required: true },
  company: { type: String, default: "" },
  customerType: {
    type: String,
    enum: ["individual", "corporate"],
    default: "individual"
  },
  joinDate: { type: Date, default: Date.now },
  status: { type: String, enum: ["active", "inactive"], default: "active" }
});
 
// Auto-increment customerId safely
customerSchema.pre("save", async function (next) {
  if (this.isNew) {
    const counter = await Counter.findOneAndUpdate(
      { name: "customerId" },
      { $inc: { seq: 1 } },
      { new: true, upsert: true }
    );
 
    this.customerId = "CUST" + String(counter.seq).padStart(5, "0");
  }
  next();
});
 
export default mongoose.model("Customer", customerSchema);