import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { verifyCodeHash, rateLimit } from "@/lib/security";
import { codeVerifySchema } from "@/lib/validators";
import { createUserSession } from "@/lib/auth";
import { LogType, CodeStatus } from "@prisma/client";

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for") ?? "unknown";

  // 5 محاولات كل 10 دقايق لكل IP — بيمنع تجربة أكواد عشوائية (brute force)
  if (!rateLimit(`code-verify:${ip}`, 5, 10 * 60 * 1000)) {
    return NextResponse.json(
      { error: "محاولات كتير، حاول تاني بعد شوية" },
      { status: 429 }
    );
  }

  const body = await req.json().catch(() => null);
  const parsed = codeVerifySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.errors[0]?.message ?? "بيانات غير صحيحة" },
      { status: 400 }
    );
  }

  const { code, deviceFingerprint } = parsed.data;

  // الكود متخزن Hash فقط، فلازم نجيب كل الأكواد الغير مستخدمة ونقارن
  // (لعدد كبير من الأكواد يفضل استخدام HMAC ثابت كـ lookup key بدل bcrypt هنا لتحسين الأداء)
  const candidates = await prisma.activationCode.findMany({
    where: { status: CodeStatus.UNUSED },
  });

  let matched = null;
  for (const candidate of candidates) {
    if (await verifyCodeHash(code, candidate.codeHash)) {
      matched = candidate;
      break;
    }
  }

  if (!matched) {
    return NextResponse.json({ error: "الكود غير صحيح أو مستخدم من قبل" }, { status: 404 });
  }

  if (matched.expiresAt && matched.expiresAt < new Date()) {
    return NextResponse.json({ error: "الكود منتهي الصلاحية" }, { status: 410 });
  }

  // TODO (المرحلة الجاية): ربط الكود بحساب مستخدم فعلي بعد تسجيل بياناته
  // هنا بنفترض إن فيه userId جاي من جلسة تسجيل مبدئية (اسم + شعبة)
  // ونربط الجهاز كجهاز أساسي لو أول مرة

  return NextResponse.json({
    ok: true,
    message: "تم التحقق من الكود بنجاح",
    codeId: matched.id,
  });
}
