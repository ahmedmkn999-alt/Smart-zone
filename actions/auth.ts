'use server';

import { prisma } from '@/lib/prisma';
import { signToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export async function loginAction(formData: FormData) {
  const email = formData.get('email') as string;
  // أضف منطق التحقق من الباسورد هنا
  
  const user = await prisma.user.findUnique({ where: { email } });
  
  if (user) {
    const token = await signToken({ userId: user.id });
    (await cookies()).set('auth_token', token, { httpOnly: true });
    return { success: true };
  }
  
  return { success: false, message: 'Invalid credentials' };
}
