import { NextRequest, NextResponse } from "next/server";
import { getUserSession } from "@/lib/auth";
import { registerTamperAttempt } from "@/lib/security";
import { z } from "zod";

const schema = z.object({
  reason: z.string().min(1).max(200),
});

// ملحوظة أمنية مهمة:
// فتح أدوات المطور F12 وحده مش دليل عبث حقيقي.
// النقطة دي بتتنادى بس لما فيه تغيير فعلي مثبت في: LocalStorage / Cookies /
// بيانات الطلبات / حالة الاشتراك / الصلاحيات — مش لمجرد محاولة فتح devtools.
export async function POST(req: NextRequest) {
  const session = await getUserSession();
  if (!session) {
    return NextResponse.json({ error: "غير مصرح" }, { status: 401 });
  }

  const body = await req.json().catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "بيانات غير صحيحة" }, { status: 400 });
  }

  const result = await registerTamperAttempt({
    userId: session.userId,
    reason: parsed.data.reason,
    ip: req.headers.get("x-forwarded-for") ?? undefined,
    userAgent: req.headers.get("user-agent") ?? undefined,
  });

  return NextResponse.json(result);
}
