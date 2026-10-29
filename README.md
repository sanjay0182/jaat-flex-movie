# JaatFlix – Direct Mode (client se kaam, server halka)

## Ye kya hai (2 line me)
- **Firebase** (Google) = sirf website ka page (`naam.web.app`). Free, bandwidth Google ka.
- **Render** = chhota backend (login, captcha, favourites, admin, chhoti JSON). Video aur images isse **nahi** guzarte.
- **User ka phone/TV/laptop** = images aur video seedha CDN se laata hai.
- Direct na chale to player apne aap **"backup"** (purana proxy) pe chala jaata hai.

```
User ──page──> Firebase (naam.web.app)
User ──JSON──> Render (backend)           [chhota, KB me]
User ──video/images──> CDN (seedha)       [Render se nahi]
```

---

## STEP 1 – GitHub pe code daalo (phone se, bina folder ke)
Is zip me **koi folder nahi hai**, saari files ek hi jagah hain. Isliye phone se upload ho jaati hain.
1. Zip ko phone me **extract** karo.
2. GitHub me nayi repo banao -> **Add file -> Upload files** -> saari files select karke upload karo -> **Commit**.
3. Ek file **haath se** banani hai (folder wali): **Add file -> Create new file**, naam me likho
   `.github/workflows/firebase.yml` (slash lagate hi folder ban jaata hai), aur `firebase-deploy.yml` file ka poora text paste karo. **Commit**.

## STEP 2 – Render (backend)
1. render.com -> **New +** -> **Web Service** -> apni GitHub repo chuno.
2. **Runtime: Docker**, **Instance: Free**.
3. **Environment Variables** me ye daalo:

| Naam | Kya likhna hai |
|---|---|
| `PUBLIC_BASE` | Render ka link, e.g. `https://jaat-api.onrender.com` (aakhir me `/` nahi) |
| `CORS_ORIGINS` | Firebase ka link, e.g. `https://naam.web.app` (2 ho to comma se: `https://naam.web.app,https://naam.firebaseapp.com`) |
| `ADMIN_KEY` | Apna admin password (jo pehle tha wahi) |
| `LINK_SECRET` | Lamba random text (jo pehle tha wahi) |
| `SQL_URL` | **Pehle wala wahi daalo** (accounts ka database) |
| `DIRECT_IMG` | `1` (images seedha). Problem aaye to `0` |
| `DIRECT_VIDEO` | `1` (video seedha). Problem aaye to `0` |

> **Zaroori:** `SQL_URL` wahi rakho jo pehle tha. Nahi daaloge to accounts Render ki local file me jaayenge, aur free Render restart pe wo file **mit jaati hai** (sab users ke account ud jaayenge).

4. **Create Web Service** dabao. Deploy hone ke baad Render ka link milega. Use `PUBLIC_BASE` me daalo (pehli baar me Render link pata nahi hota, to deploy ke baad env edit karke save karo, wo khud redeploy karega).

## STEP 3 – Firebase (page) – GitHub se apne aap deploy
1. console.firebase.google.com -> **Add project** -> naam do. **Project ID** note karo (wahi `naam.web.app` banta hai).
2. Firebase me **Build -> Hosting -> Get started** karke site activate karo.
3. Firebase **Project settings -> Service accounts -> Generate new private key**. Ek `.json` file download hogi.
4. GitHub repo -> **Settings -> Secrets and variables -> Actions -> New repository secret**:
   - `FIREBASE_SERVICE_ACCOUNT` = us `.json` file ka **poora text**
   - `FIREBASE_PROJECT_ID` = Firebase ka Project ID
5. GitHub me `config.js` kholo (pencil), `https://YOUR-APP.onrender.com` ki jagah apna **Render link** likho -> Commit.
6. Commit hote hi **Actions** tab me deploy chalega (1-2 min). Hone ke baad `https://naam.web.app` khulega.
(Laptop ho to purana tareeka bhi chalega: `firebase deploy --only hosting`, bas pehle `public/` folder bana ke files usme rakhni hongi.)

## STEP 4 – Test (zaroor karo)
1. `https://naam.web.app` kholo. Home aur posters aane chahiye.
2. Ek **movie** chalao. Video chal gayi = direct sahi.
3. Agar chalte time "Trying another source..." dikhe aur chal jaye = direct block tha, backup chal gaya (kaam theek, bas server thoda use hua).
4. Login/signup karke dekho, captcha aaye to solve karo.

## Problem aaye to
| Problem | Kya karo |
|---|---|
| Posters nahi dikh rahe | Render me `DIRECT_IMG=0` |
| Video nahi chal rahi | Render me `DIRECT_VIDEO=0` |
| Site khulti hai par data nahi aata | `CORS_ORIGINS` me Firebase ka link sahi (https ke saath, aakhir me `/` nahi) |
| Data nahi aata, Render link galat | `public/config.js` ka `API_BASE` check karo, phir dobara `firebase deploy` |
| Pehli request dheemi | Free Render 15 min idle me sota hai. Keepalive bot chalate raho |
| Admin panel | `https://RENDER-LINK/admin` (Firebase pe nahi) |

## Dhyan rakho
- Direct links me link-signing nahi hoti, koi link copy karke share kar sakta hai.
- `DIRECT_IMG` / `DIRECT_VIDEO` badalne ke baad sirf Render redeploy karna hai, Firebase dobara nahi.
- Free Render ka bandwidth bachane ke liye video/images direct hi rakho.
