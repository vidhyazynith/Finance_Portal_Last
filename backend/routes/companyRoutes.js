import express from "express";
import Company from '../models/Company.js';
import { authenticateToken, requireRole } from '../middleware/auth.js';
import { getCompany, updateCompany } from "../Controllers/companyController.js";

const router = express.Router();

/* ==========================
   GET Company Info
========================== */
router.get("/", authenticateToken, requireRole('admin'), getCompany);

/* ==========================
   PUT Company Info (Update or Create)
========================== */
router.put("/", authenticateToken, requireRole('admin'), updateCompany);

export default router;
