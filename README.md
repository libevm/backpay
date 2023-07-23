# Backpay

Paymasters that backrun.

TL;DR - Paymasters can sponsor transactions for other users. However, there is no incentive for sponsoring a transaction for a user. What if we incorporated [mev-backrunning](https://www.mev.wiki/attack-examples/back-running) into Paymasters? 

That way users with tokens (but not the native gas token) can be sponsored, especially if the tokens are volatile meme coins (which usually results in juicy backrunning opportunities).

#$ PoC (Polygon)

```bash
https://polygonscan.com/tx/0xed33f8c333fd6be0e0d7a759ed6431e51e691dce495314d2a31492ced7502ce6

https://www.jiffyscan.xyz/bundle/0xed33f8c333fd6be0e0d7a759ed6431e51e691dce495314d2a31492ced7502ce6?network=matic&pageNo=0&pageSize=10
```