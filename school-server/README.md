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

## Student registration approval (v0005)

- `POST /api/students` creates a pending request only; it does not create a student row or a student session.
- `GET /api/registration/status` checks the request using its private bearer token.
- `POST /api/registration/claim` creates a student session only after approval.
- `GET /api/admin/registration-requests` and `POST /api/admin/registration-requests/:id/decision` are protected by administrator authentication.
- The unique key in `student_name_registry` reserves a normalized full name while a request is pending and after approval. Rejection releases the reservation.

The migration file is `migrations/0005_student_registration_approval.sql`. It has already been applied manually through Cloudflare D1 Console in this deployment workflow. Do not run it again if the tables/index already exist; its statements are idempotent, but the initial population only inserts missing registry keys. For a fresh database, execute the complete migration once in D1 Console before deploying the Worker.

## Deploy without a Cloudflare terminal

Push the Worker project files to the connected GitHub repository and let the configured Cloudflare deployment run. Keep `wrangler.jsonc` and its D1 binding intact. Never commit Worker secrets such as `ADMIN_PASSWORD`, `RATE_LIMIT_SECRET`, `BOUMDIENE_INITIAL_PASSWORD`, or `VAPID_PRIVATE_JWK`.


## حماية فضاء الأستاذ وربط الأفواج
- كل مسارات `/api/teacher/*` (عدا تسجيل الدخول) تتطلب جلسة صادرة عن `/api/teacher/login`، ولا يمكن للإدارة انتحال الأستاذ عبر `teacher_id` في الرابط.
- إنشاء فوج من لوحة الإدارة يتطلب `teacher_id` و`teacher_password`. يتحقق Worker من كلمة مرور الأستاذ المخزنة على شكل hash قبل ربط الفوج به.
- يجب نشر Worker المحدّث مع لوحة الإدارة المحدّثة حتى تعمل هذه الحماية.
