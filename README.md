# أداة فحص ثغرات المواقع (Web Vulnerability Scanner)

هذه الأداة تقوم بالبحث عن الثغرات الأمنية المحتملة في المواقع وحفظ النتائج في مستودع GitHub الخاص بك.

## المتطلبات

1. Python 3.7 أو أحدث
2. حساب GitHub وتوكن الوصول الشخصي (Personal Access Token)
3. المكتبات المطلوبة (يمكن تثبيتها باستخدام الأمر التالي):
```bash
pip install -r requirements.txt
```

## كيفية الاستخدام

1. قم بتثبيت المتطلبات أولاً:
```bash
pip install -r requirements.txt
```

2. قم بتشغيل الأداة باستخدام الأمر التالي:
```bash
python scan1.py <رابط_الموقع> <github_token> <اسم_المستودع>
```

مثال:
```bash
python scan1.py example.com ghp_your_token_here my_vulnerability_scan
```

## المخرجات

- ستقوم الأداة بالبحث في قواعد بيانات الثغرات المعروفة
- سيتم حفظ النتائج في ملف JSON في المستودع المحدد على GitHub
- يمكنك مراجعة النتائج في ملف `vulnerability_report.json` في المستودع

## ملاحظات مهمة

- تأكد من استخدام توكن GitHub صالح مع الصلاحيات المناسبة
- استخدم الأداة بمسؤولية وفقط على المواقع المصرح لك بفحصها
- النتائج قد تتضمن نتائج إيجابية خاطئة، لذا يجب التحقق منها يدوياً

## المصادر المستخدمة للبحث

- Exploit Database
- National Vulnerability Database (NVD)
- Common Vulnerabilities and Exposures (CVE)