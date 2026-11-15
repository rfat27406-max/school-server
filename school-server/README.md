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


## تفعيل Web Push والتذكير التلقائي

1. نفّذ ملف `migrations/0004_web_push.sql` على قاعدة D1 الحالية مرة واحدة فقط. من D1 Console نفّذ كل عبارة SQL منفردة، ولا تكرر `ALTER TABLE bookings ADD COLUMN reminder_sent_at TEXT` إذا نجحت.
2. في إعدادات Worker > Settings > Variables and Secrets أضف Secret باسم `VAPID_PRIVATE_JWK` (قيمة المفتاح الخاص تُسلّم بشكل منفصل)، واترك `VAPID_PUBLIC_KEY` و`VAPID_SUBJECT` كمتغيرات عادية في `wrangler.jsonc`.
3. أضف Cron Trigger في Worker > Settings > Triggers: `*/5 * * * *` (كل خمس دقائق).
4. انشر Worker الجديد، ثم انشر مشروع التلميذ الذي يحتوي `sw.js`. يجب أن يعمل موقع التلميذ عبر HTTPS.
5. يفتح التلميذ الإعدادات ويفعّل «الإشعارات والتذكير قبل الحصة»، ثم يسمح للمتصفح. الاشتراك مرتبط بهذا الجهاز وهذا الحساب.
6. اختبر بإرسال إشعار عام من الإدارة. تذكير الحصة يُرسل آلياً قبل 30 دقيقة تقريباً وفق توقيت الجزائر، ويُعالج الخادم الحجوزات مرة كل خمس دقائق.

لا تضع `VAPID_PRIVATE_JWK` داخل ملفات الواجهة أو المستودع. إذا غيّرت زوج مفاتيح VAPID لاحقاً، يجب على الأجهزة إعادة الاشتراك بالمفتاح العام الجديد.
