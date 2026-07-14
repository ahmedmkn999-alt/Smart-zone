import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";

const SECRET = new TextEncoder().encode(process.env.JWT_SECRET || "");
const COOKIE_NAME = "sz_admin_session";
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 ساعات

export interface AdminSessionPayload {
  adminId: string;
  email: string;
  role: string;
}

// إنشاء JWT وتخزينه في HttpOnly + Secure + SameSite cookie
export async function createAdminSession(payload: AdminSessionPayload) {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured");
  }

  const token = await new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${SESSION_TTL_SECONDS}s`)
    .sign(SECRET);

  const cookieStore = await cookies();
  cookieStore.set(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
}

export async function getAdminSession(): Promise<AdminSessionPayload | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get(COOKIE_NAME)?.value;
  if (!token) return null;

  try {
    const { payload } = await jwtVerify(token, SECRET);
    return payload as unknown as AdminSessionPayload;
  } catch {
    return null;
  }
}

export async function destroyAdminSession() {
  const cookieStore = await cookies();
  cookieStore.delete(COOKIE_NAME);
}

// نفس المنطق لسيشن الطالب (كوكي منفصلة sz_user_session) — نفس الإعدادات الأمنية
const USER_COOKIE_NAME = "sz_user_session";
const USER_SESSION_TTL = 60 * 60 * 24 * 30; // شهر، بنفس مدة الاشتراك

export interface UserSessionPayload {
  userId: string;
  deviceFingerprint: string;
}

export async function createUserSession(payload: UserSessionPayload) {
  const token = await new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${USER_SESSION_TTL}s`)
    .sign(SECRET);

  const cookieStore = await cookies();
  cookieStore.set(USER_COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: USER_SESSION_TTL,
  });
}

export async function getUserSession(): Promise<UserSessionPayload | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get(USER_COOKIE_NAME)?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, SECRET);
    return payload as unknown as UserSessionPayload;
  } catch {
    return null;
  }
}

export async function destroyUserSession() {
  const cookieStore = await cookies();
  cookieStore.delete(USER_COOKIE_NAME);
}
