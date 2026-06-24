# מדריך העלאה ל-Google Play — אפליקציית AntiPhishing

מדריך זה מסביר **שלב-אחר-שלב** מה צריך לעשות כדי לפרסם את האפליקציה בחנות.
חולק לשני חלקים: (א) מה שכבר תיקנתי בקוד, (ב) מה שאתה צריך לעשות.

---

## חלק א' — מה כבר תוקן עבורך (בקוד)

| # | מה תוקן | למה זה חשוב לחנות |
|---|---------|------------------|
| 1 | **אייקון חדש (Adaptive Icon)** — המגן גדול וממלא את כל האייקון, על רקע נייבי, **בלי הלבן מסביב**. | בלי adaptive icon אנדרואיד עוטף את האייקון בריבוע לבן. עכשיו זה נפתר. |
| 2 | **הוסרה התראת הדיבאג** ("AntiPhishing Debug — System is ALIVE") שהופיעה למשתמש כל 15 דקות. | התראת דיבאג למשתמשים אמיתיים = פסילה / ביקורות רעות. |
| 3 | **הוסר ה-Toast** "Step 3 not built yet. Lexical analysis complete…" שהוצג למשתמש. | הודעת פיתוח שנחשפת למשתמש קצה. |
| 4 | **בוטל `usesCleartextTraffic`** (שריד מבדיקות מקומיות ב-HTTP). | השרת בפרודקשן הוא HTTPS; דרישת אבטחה של החנות. |
| 5 | **הוסרה הרשאת `POST_NOTIFICATIONS`** שכבר לא בשימוש. | פחות הרשאות = אישור מהיר יותר וטופס Data Safety פשוט יותר. |
| 6 | **נוצר אייקון חנות 512×512** בקובץ `store-assets/play-store-icon-512.png`. | חובה להעלאת החנות. |
| 7 | **נוצרה ופורסמה מדיניות פרטיות** דו-לשונית באתר ה-Firebase שלך (אותו אתר של שאר האפליקציות). | חובה — צריך קישור פומבי (ראה שלב 4). |

> ✅ הקוד נבדק — ה-build עובר (`./gradlew :app:assembleDebug` → BUILD SUCCESSFUL).

---

## חלק ב' — מה אתה צריך לעשות

### שלב 0 — קובץ החתימה (Keystore) — ⚠️ הכי חשוב

כבר קיים `app/release/app-release.aab` שנבנה ונחתם דרך Android Studio.
ה-**keystore** (קובץ `.jks`/`.keystore`) שאיתו חתמת + הסיסמאות —
**שמור אותם לנצח וגבה אותם** (ענן + דיסק חיצוני).

* אם תאבד את ה-keystore — **לא תוכל יותר לעדכן את האפליקציה בחנות**. אי אפשר להחליף אותו.
* רשום בצד: נתיב הקובץ, סיסמת ה-keystore, ה-alias וסיסמת ה-alias.

> המלצה: בהעלאה הראשונה Google יציע **Play App Signing** — קבל אותו. אז Google שומר את
> מפתח החתימה הסופי, ואתה רק צריך לשמור את ה-*upload key*.

### שלב 1 — לבנות AAB חתום מחדש

ה-AAB הקיים נבנה **לפני** התיקונים שלי. צריך לבנות מחדש:

1. ב-Android Studio: **Build → Generate Signed App Bundle / APK → Android App Bundle**.
2. בחר את ה-keystore הקיים (אותו אחד מקודם) → הזן סיסמאות → בחר alias.
3. Build Variant: **release** → Finish.
4. הקובץ ייווצר ב-`app/release/app-release.aab` — זה מה שמעלים לחנות.

> טיפ (לא חובה): אפשר להפוך את זה לאוטומטי עם `./gradlew bundleRelease`. ראה נספח א'.

### שלב 2 — חשבון Google Play Console

1. היכנס ל-<https://play.google.com/console> והירשם כמפתח.
2. עלות חד-פעמית: **$25**.
3. אמת זהות (ת"ז/דרכון) — בחשבון אישי זה יכול לקחת כמה ימים, אז התחל מוקדם.
4. **Create app** → שם: `AntiPhishing` → שפת ברירת מחדל → סוג: **App** → חינמי (Free).

### שלב 3 — למלא את פרטי האפליקציה ("Set up your app")

ב-Play Console יש רשימת משימות. אלה התשובות עבור האפליקציה הזו:

**App access (גישה לאפליקציה):**
האפליקציה זמינה לכולם בלי התחברות → בחר *"All functionality is available without special access"*.

**Ads (פרסומות):** אין פרסומות → *"No, my app does not contain ads"*.

**Content rating (דירוג תוכן):** מלא את שאלון ה-IARC. זו אפליקציית כלי/אבטחה בלי תוכן בעייתי →
התוצאה תהיה כנראה **Everyone / PEGI 3**. ענה בכנות (אין אלימות, אין תוכן מיני וכו').

**Target audience (קהל יעד):** בחר **13+** (לא מיועד לילדים) — כדי להימנע ממדיניות Families.

**Data safety (בטיחות נתונים):** ⚠️ חשוב — ראה שלב 5 לתשובות המדויקות.

**Government apps / Financial / Health:** לא → דלג.

**Category:** בחר **Tools** (כלים). אפשר גם להוסיף תגיות.

### שלב 4 — מדיניות הפרטיות (כבר מאוחסנת ב-Firebase שלך)

מדיניות הפרטיות נוצרה ונפרסת לאתר ה-Firebase הקיים שלך (`rongo-privacy`), יחד עם שאר
האפליקציות. הקובץ: `public/antiphishing-privacy.html` (דו-לשוני, מייל `rongoapp2026@gmail.com`).

הקישור הפומבי שתדביק ב-Play Console תחת **Store settings → Privacy Policy**:

```
https://rongo-privacy.web.app/antiphishing-privacy
```

> אם תעדכן את ה-HTML בעתיד, הרץ שוב `firebase deploy --only hosting` מתוך תיקיית
> `checkchange-privacy-main` כדי שהשינוי יעלה לאוויר.

### שלב 5 — טופס Data Safety (התשובות המדויקות לאפליקציה שלך)

* **Does your app collect or share user data?** → **Yes**
  (כי כתובות הקישורים נשלחות לשרת לבדיקה).
* **Data type:** תחת *Web browsing history* → סמן שנאסף.
  * Purpose: **App functionality** + **Fraud prevention, security, and compliance**.
  * Collected (כן). **Shared: No** (השרת שלך הוא ספק השירות שלך, לא צד שלישי לפרסום).
  * **Is this data processed ephemerally?** — אם השרת שלך **לא שומר** את הכתובות, סמן "כן";
    אם הוא כן רושם/שומר אותן, סמן "לא" (תהיה כן — לפי ההתנהגות האמיתית של השרת).
* **Is all data encrypted in transit?** → **Yes** (HTTPS).
* **Can users request data deletion?** → ההיסטוריה המקומית נמחקת בכפתור "נקה היסטוריה" באפליקציה.
* **לא** נאספים: מיקום, אנשי קשר, מזהי מכשיר, תמונות וכו'.

> חשוב: הטופס הזה חייב להתאים למה שכתוב במדיניות הפרטיות ולמה שהשרת באמת עושה.

### שלב 6 — דף החנות (Store Listing)

נדרשים הנכסים הבאים. הכנתי טקסטים מוכנים בנספח ב'.

| נכס | דרישה | סטטוס |
|-----|-------|-------|
| App icon | 512×512 PNG | ✅ `store-assets/play-store-icon-512.png` |
| Feature graphic | 1024×500 PNG/JPG | ❌ צריך ליצור (באנר עליון) |
| Phone screenshots | לפחות 2 (עד 8), יחס 16:9 או 9:16 | ❌ צלם מהאפליקציה |
| כותרת קצרה | עד 30 תווים | ראה נספח ב' |
| תיאור קצר | עד 80 תווים | ראה נספח ב' |
| תיאור מלא | עד 4000 תווים | ראה נספח ב' |

> צילומי מסך: הרץ את האפליקציה (מסך הבית עם המגן, מסך "קישור זדוני נחסם", מסך החיווי הירוק)
> וצלם. אפשר במכשיר אמיתי או באמולטור (Volume Down + Power, או כפתור הצילום באמולטור).
> ל-Feature graphic אפשר להשתמש באייקון 512 על רקע נייבי עם הכותרת — אשמח להכין לך אם תרצה.

### שלב 7 — לפרסם (Release)

1. **Testing → Internal testing** קודם (מומלץ!): צור Release, העלה את ה-AAB, הוסף את המייל שלך
   כבודק, והתקן דרך הקישור — לוודא שהכל עובד אצל משתמש אמיתי.
2. כשהכל תקין: **Production → Create new release** → העלה את ה-AAB → מלא "Release notes" →
   **Review release** → **Start rollout to Production**.
3. הביקורת של Google אורכת בדרך כלל **כמה ימים** (לפעמים יותר בהעלאה ראשונה). תקבל מייל.

---

## המלצות נוספות (לא חוסם, אבל חשוב)

1. **⏱️ ה"שינה" של שרת Render (חינמי).** השרת נרדם אחרי ~15 דק' חוסר פעילות ומתעורר ~50 שניות.
   המשמעות: הקישור הראשון אחרי הפסקה ייפתח לאט מאוד (יש Spinner + כפתור "פתח בכל זאת" כגיבוי).
   לחוויה תקינה — שדרג את Render לתוכנית always-on, או הוסף "פינג" תקופתי שמשאיר אותו ער.
   *(לא נגעתי בשרת לבקשתך.)*
2. **גרסה.** `versionCode = 1`, `versionName = "1.0"` — תקין להשקה. לכל עדכון עתידי בחנות
   חובה להעלות את `versionCode` ב-1.
3. **כיווץ קוד (R8).** כרגע `isMinifyEnabled = false`. אפשר להפעיל כיווץ להקטנת גודל,
   אבל לא חובה ויש סיכון קל (Hilt/Room) — בדוק טוב לפני. השאר כבוי להשקה הראשונה.
4. **גיבוי ענן של ההיסטוריה.** `allowBackup=true` מגבה את היסטוריית הקישורים לענן Google.
   זה תקין, רק שים לב שזה מתועד במדיניות הפרטיות.

---

## נספח א' — חתימה אוטומטית עם Gradle (אופציונלי)

כדי לבנות AAB חתום מהטרמינל (`./gradlew bundleRelease`) בלי האשף:

1. צור קובץ `keystore.properties` בשורש הפרויקט (אל תעלה ל-Git!):
   ```properties
   storeFile=C:/path/to/your-key.jks
   storePassword=****
   keyAlias=****
   keyPassword=****
   ```
2. הוסף ל-`.gitignore` את השורה `keystore.properties`.
3. ב-`app/build.gradle.kts`, בתוך `android { }`, הוסף `signingConfigs` וקשר ל-`release`.
   אשמח להוסיף לך את הקוד אם תרצה ללכת בדרך הזו.

## נספח ב' — טקסטים מוכנים לדף החנות

**כותרת קצרה (עד 30):**
`AntiPhishing — הגנה מקישורים`

**תיאור קצר (עד 80):**
`בודק כל קישור שאתה פותח וחוסם אתרי פישינג והונאה לפני שהם נטענים.`

**תיאור מלא (עברית):**
```
AntiPhishing מגן עליך מפני קישורי פישינג ואתרים זדוניים — בזמן אמת.

כשמפעילים את ההגנה, כל קישור שאתה פותח נבדק אוטומטית מול מאגר אתרי פישינג מעודכן
ובאמצעות ניתוח חכם של הכתובת, עוד לפני שהדף נטען. אם הקישור מסוכן — תקבל אזהרה ברורה
ותוכל לחזור אחורה. אם הוא בטוח — הוא נפתח כרגיל בדפדפן שבחרת.

✔ בדיקה אוטומטית של כל קישור
✔ אזהרה מיידית על אתרי פישינג והונאה
✔ ניתוח כתובת חכם על המכשיר
✔ היסטוריית סריקות וסטטיסטיקות — נשמרות אצלך בלבד
✔ תמיכה בעברית ובאנגלית
✔ בלי חשבון, בלי פרסומות, בלי מעקב

הפרטיות שלך חשובה לנו: האפליקציה לא דורשת הרשמה ולא אוספת מידע אישי.
```

**תיאור מלא (אנגלית):**
```
AntiPhishing protects you from phishing and malicious links — in real time.

When protection is on, every link you open is automatically checked against an
up-to-date phishing database and a smart on-device address analysis, before the
page loads. If a link is dangerous, you get a clear warning and can go back. If it
is safe, it opens normally in your chosen browser.

✔ Automatic check of every link you open
✔ Instant warning for phishing and scam sites
✔ Smart on-device URL analysis
✔ Scan history & stats — stored only on your device
✔ Hebrew and English support
✔ No account, no ads, no tracking

Your privacy matters: the app requires no sign-up and collects no personal data.
```
