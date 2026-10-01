>A.1

>A.2
A.2 錄影腳本 (step 1、2、5 live)

Step 1 — Discovery

口白：「In A.1 the login only tells me success or failure, never the data. That success/failure bit is a boolean oracle — I can ask yes/no questions about the admin password.」

畫面：在 Burp Repeater 送 admin' AND '1'='1' -- （→ 302 成功）和 admin' AND '1'='2' -- （→ 200 Invalid），示範一真一假。

Step 2 — Exploitation（live 跑 script）

口白：「My script turns that into character extraction. It finds the length, then asks substr(password,pos,1)='c' for each position.」
指令：python3 exploit_sqli.py
畫面：讓它現場跑完，印出 adm-ec6031eba6c7 + "Verified: logged in as admin"。
接著在瀏覽器用該密碼實際登入 admin，顯示 Welcome, admin。

Step 5 — Verification

畫面：切到修好版，再跑一次同一支 script。
口白：「Against the parameterised version, every oracle query returns Invalid, so it can't recover anything.」
畫面：script 卡住 / 找不到長度 / 印不出密碼。

>B.1
Step 1：口白「notes feature redisplays my input. I test with <b>test</b> — it renders as bold, so output isn't escaped.」示範存 <b>test</b> 變粗體。

Step 2：存 <script>alert('XSS by 36409251')</script>，重整 → 跳 alert。再存 <script>alert(document.cookie)</script> → 顯示 cookie。口白講 impact（stored、會在 admin 瀏覽器執行、cookie 無 HttpOnly）。

Step 5：切修好版，存同樣 payload，重整 → 只顯示文字、不跳 alert。

