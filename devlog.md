(8/11)

Initiated the project, update for the EVE, the plans are following:<br>
add more engine, add digital signature,  Caesar / Affine / Vigenère / Hill | HMAC-SHA256 | Timestamp | SSCI via shared secret.<br>
We will see how this works, already spotted logic leaking, my agent made a code by only looking at ui codes... <br> 
In the middle of updating engine, tomorrow I will continue from Hill cipher. <br>

(8/12)<br>
Continue the project, writing from Hill Cipher. <br>
This is very challenging, has lots of bounce bump, not only I need to make sure code runs, I also need to think about what's more efficiency or not. <br>

(8/13)<br>
part1<br>
Continued, phase 1 confirmed by podos and orion, and mini-dante, run the test,<br>
🚀 Starting Grand Arsenal Audit for: 'Imperial Protocol v2.1 - Hello PODO!'

------------------------------------------------------------
✅ [0x01] Caesar     : SUCCESS
    └─ Ciphertext(hex): 73979a8f9c938b964a7a9c999e998d99964aa05c585b4a574a...
✅ [0x02] Affine     : SUCCESS
    └─ Ciphertext(hex): 4e6a97f2b52eb65be7b7b588d388d4885be7f1f5b9e6e7aae7...
✅ [0x03] Vigenere   : SUCCESS
    └─ Ciphertext(hex): 90bfb1b5b7c8b1bb7795c4b6c6b0b3b4cb70c5897383677f61...
✅ [0x04] Hill       : SUCCESS
    └─ Ciphertext(hex): 5ee581775b9d86eda0ff865383b23cdaa3b8a2ea3c533f97e5...
🏆 All engines are operational and algebraically sound!
and output looks solid. 
part2<br>
initiated phase 2 with Orion, waiting for Dante's response. 
it kinda make sense why for all lecture notes and textbooks says (keyGen, Enc, Dec) and they are all written as Tuple <br>
gosh, I was working on protocol_engine today and Orion only gave me 2 engines, is this a sign of drift or lazyness. For real<br>

(8/17)
Continue on the project starting with Dante's comments. <br> 
First, Artisan vs Efficiency, currently my Hill code does modular at the end, but to reduce computation time, doing modulars<br>
between each recursive step is better. <br> 
Second, no mod_inverse in encryption, for efficiency use when decrypt but no encrypt <br>
Before moving back to phase 2 updating script test: one, add Edge cases, Two, add affine invalid key text<br>
Passed all test with edge cases. 