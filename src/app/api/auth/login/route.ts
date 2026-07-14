import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { verifyPassword } from "@/lib/security";
import { createAdminSession } from "@/lib/auth";
import { adminLoginSchema } from "@/lib/validators";
import { rateLimit } from "@/lib/security";
import { LogType } from "@prisma/client";

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for") ?? "unknown";

  // Rate limiting: 5 محاولات كل 10 دقايق لكل IP
  if (!rateLimit(`admin-login:${ip}`, 5, 10 * 60 * 1000)) {
    return NextResponse.json(
      { error: "محاولات كتير، حاول تاني بعد شوية" },
      { status: 429 }
    );
  }

  const body = await req.json().catch(() => null);
  const parsed = adminLoginSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.errors[0]?.message ?? "بيانات غير صحيحة" },
      { status: 400 }
    );
  }

  const { email, password } = parsed.data;

  const admin = await prisma.admin.findUnique({ where: { email } });
  if (!admin) {
    return NextResponse.json({ error: "بيانات الدخول غير صحيحة" }, { status: 401 });
  }

  const validPassword = await verifyPassword(password, admin.passwordHash);
  if (!validPassword) {
    return NextResponse.json({ error: "بيانات الدخول غير صحيحة" }, { status: 401 });
  }

  await createAdminSession({ adminId: admin.id, email: admin.email, role: admin.role });

  await prisma.admin.update({ where: { id: admin.id }, data: { lastLoginAt: new Date() } });

  await prisma.log.create({
    data: {
      type: LogType.LOGIN,
      message: `تسجيل دخول أدمن: ${admin.email}`,
      adminId: admin.id,
      ip,
      userAgent: req.headers.get("user-agent") ?? undefined,
    },
  });

  return NextResponse.json({ ok: true });
}
