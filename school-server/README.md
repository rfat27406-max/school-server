# school-server

Cloudflare Worker API لمنصة مدرستي، مع قاعدة بيانات Cloudflare D1.

## إعدادات البيئة
- D1 binding باسم `DB`.
- Cloudflare Secret باسم `ADMIN_PASSWORD`.
- Cloudflare Secret باسم `RATE_LIMIT_SECRET`.
- Cloudflare Secret باسم `BOUMDIENE_INITIAL_PASSWORD` لتعيين كلمة مرور بومدين أول مرة إذا كان `password_hash` فارغاً.
- `ALLOWED_ORIGINS` يجب أن يحتوي عناوين واجهات Pages المسموح لها بالاتصال.

## الوظائف
- جلسات دخول مستقلة للإدارة والأساتذة والتلاميذ.
- إضافة أساتذة مع `password_hash`، ولكل أستاذ أفواجه وبياناته.
- الإدارة تستطيع اختيار الأستاذ في لوحة التحكم واستعراض فضائه عبر مسارات `/api/teacher/*` مع `teacher_id` في query؛ هذا الاختيار متاح فقط مع جلسة إدارة صالحة.
- الأستاذ العادي لا يستطيع اختيار `teacher_id` آخر؛ هوية الأستاذ تؤخذ من جلسة الدخول.
- ملخصات مالية عامة وخاصة بكل أستاذ.
- إشعارات داخل المنصة للجميع أو لتلميذ محدد، مع سجل إداري.

## الإشعارات
المسار `POST /api/admin/notifications` ينشر الإشعار في جدول `notifications`، والمسار `GET /api/notifications` يعرض إشعارات التلميذ المسجل. والمسار `GET /api/admin/notifications` يعرض سجل الإدارة.
هذا الإصدار لا ينفذ Web Push عند إغلاق الموقع. يتطلب ذلك إعداد VAPID وService Worker وتخزين اشتراكات Push وخدمة إرسال وجدولة.

## ترحيلات D1
تأكد من تطبيق ملفات migrations على قاعدة البيانات البعيدة قبل نشر الوظائف التي تعتمد عليها:
- `0002_auth_teachers_notifications.sql`
- `0003_student_daily_group_limit.sql`

لا تعِد تنفيذ جمل `ALTER TABLE ... ADD COLUMN` بعد نجاحها؛ تحقق من وجود العمود أولاً.
