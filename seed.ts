import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  // ---------- FAQ ----------
  const faqs = [
    { question: "ما سعر الاشتراك؟", answer: "300 جنيه.", order: 1 },
    {
      question: "كيف أشترك؟",
      answer: "حول المبلغ على: 01114672635، ثم أرسل صورة التحويل داخل الموقع.",
      order: 2,
    },
    { question: "مدة الاشتراك؟", answer: "30 يوم.", order: 3 },
    { question: "هل يوجد تجربة؟", answer: "نعم، تجربة مجانية لمدة ساعة.", order: 4 },
    {
      question: "كيف أحصل على الكود؟",
      answer: "بعد مراجعة الدفع يتم إرسال الكود.",
      order: 5,
    },
    {
      question: "هل الكود يعمل مرتين؟",
      answer: "لا، مرة واحدة فقط.",
      order: 6,
    },
    {
      question: "هل يمكن تغيير الجهاز؟",
      answer: "نعم، عن طريق طلب تغيير جهاز.",
      order: 7,
    },
  ];

  for (const faq of faqs) {
    const exists = await prisma.fAQ.findFirst({ where: { question: faq.question } });
    if (!exists) await prisma.fAQ.create({ data: faq });
  }

  console.log("✅ Seed تم بنجاح (FAQ). ملحوظة: جدول Teachers لسه متأجل حسب الطلب.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
