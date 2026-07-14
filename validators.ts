import { z } from "zod";

export const adminLoginSchema = z.object({
  email: z.string().email("بريد إلكتروني غير صحيح"),
  password: z.string().min(8, "كلمة المرور قصيرة جدًا"),
});

export const codeVerifySchema = z.object({
  code: z
    .string()
    .length(9, "الكود لازم يكون 9 أرقام")
    .regex(/^\d{9}$/, "الكود لازم يتكون من أرقام فقط"),
  deviceFingerprint: z.string().min(10),
});

export const createCodeSchema = z.object({
  count: z.number().int().min(1).max(100).default(1),
  expiresInDays: z.number().int().min(1).max(365).default(30),
});

export const supportMessageSchema = z.object({
  ticketId: z.string().uuid().optional(),
  subject: z.string().min(3).max(120).optional(),
  body: z.string().min(1).max(2000),
  imageUrl: z.string().url().optional(),
});

export const deviceChangeRequestSchema = z.object({
  newFingerprint: z.string().min(10),
});

export const faqSchema = z.object({
  question: z.string().min(3).max(300),
  answer: z.string().min(1).max(2000),
  order: z.number().int().optional(),
  isActive: z.boolean().optional(),
});

export const subjectSchema = z.object({
  title: z.string().min(1).max(120),
  imageUrl: z.string().url(),
  track: z.string().min(1),
  order: z.number().int().optional(),
  isActive: z.boolean().optional(),
});
