import bcrypt from "bcryptjs";
import { prisma } from "./db";
import { LogType } from "@prisma/client";

const MAX_TAMPER_ATTEMPTS = 3;

// ---------- Activation code hashing ----------
// الكود بيتخزن كـ Hash بس، أبدًا نص عادي
export async function hashCode(code: string): Promise<string> {
  return bcrypt.hash(code, 12);
}

export async function verifyCodeHash(code: string, hash: string): Promise<boolean> {
  return bcrypt.compare(code, hash);
}

export function generateNineDigitCode(): string {
  // 9 أرقام، أول رقم مش صفر عشان نضمن طول ثابت
  const first = Math.floor(Math.random() * 9) + 1;
  const rest = Array.from({ length: 8 }, () => Math.floor(Math.random() * 10)).join("");
  return `${first}${rest}`;
}

// ---------- Password hashing (admin) ----------
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// ---------- Tamper detection ----------
// بيتسجل في Logs + بيزود tamperCount بتاع اليوزر، وبعد 3 محاولات:
// إنهاء الجلسة + تعطيل الكود مؤقتًا + إشعار للأدمن
export async function registerTamperAttempt(params: {
  userId: string;
  reason: string;
  ip?: string;
  userAgent?: string;
}) {
  const { userId, reason, ip, userAgent } = params;

  const user = await prisma.user.update({
    where: { id: userId },
    data: { tamperCount: { increment: 1 } },
  });

  await prisma.log.create({
    data: {
      type: LogType.TAMPER_ATTEMPT,
      message: reason,
      userId,
      ip,
      userAgent,
    },
  });

  if (user.tamperCount >= MAX_TAMPER_ATTEMPTS) {
    await prisma.user.update({
      where: { id: userId },
      data: { isLocked: true, lockedAt: new Date() },
    });

    // تعطيل أي كود مفعّل مرتبط بالمستخدم
    await prisma.activationCode.updateMany({
      where: { userId, status: "USED" },
      data: { status: "DISABLED", disabledReason: "تجاوز عدد محاولات العبث المسموح بها" },
    });

    await prisma.notification.create({
      data: {
        type: LogType.TAMPER_ATTEMPT,
        title: "🚫 تعطيل حساب تلقائي",
        body: `تم تعطيل حساب المستخدم بعد ${MAX_TAMPER_ATTEMPTS} محاولات عبث`,
        userId,
      },
    });

    return { locked: true };
  }

  return { locked: false, attemptsLeft: MAX_TAMPER_ATTEMPTS - user.tamperCount };
}

// ---------- Simple in-memory rate limiter ----------
// ملحوظة: في بيئة إنتاج متعددة السيرفرات (serverless) يفضّل استبداله بـ Redis (مثل Upstash)
const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = rateLimitStore.get(key);

  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  if (entry.count >= limit) return false;

  entry.count++;
  return true;
}
