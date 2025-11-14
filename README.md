# 🔐 Custom Cipher: Playfair + Hill Combo

> *"When you combine two old ciphers and hope nobody notices the math still works against you"* 🤓

![Crypto Meme](https://media.giphy.com/media/LmNwrBhejkK9EFP504/giphy.gif)

---

## 🚀 Quick Overview

This project implements a **hybrid classical cipher** combining **Playfair** (digraph substitution) and **Hill** (linear algebra transformation) ciphers. We built it, broke it, and learned why modern crypto exists!

---

## ⚡ Features

- **Two-Layer Encryption**: Playfair → Hill pipeline
- **Cryptanalysis Tools**: Known-plaintext & frequency analysis attacks
- **Performance Benchmarking**: Compare with classical ciphers
- **Security Assessment**: Full vulnerability analysis

---

## 🎯 Key Findings
| Strength ✅ | Weakness ❌ |
|-------------|-------------|
| Good against frequency analysis | Broken by known-plaintext attacks |
| Better than single classical ciphers | Hill matrix recoverable with 9+ chars |
| Educational value | Deterministic encryption |
---

## 🛠️ Quick Start

```bash
# Run the full demo
python playfair_hill_attack.py --demo

# Generate security report
python playfair_hill_attack.py --report

# Custom attack
python playfair_hill_attack.py --attack --ciphertext "ZKFQZTYXQ..." --known-plain "HELLO" --playfair-key "SECURITYKEY"
```
---

## 📊 Performance Snapshot

| Operation | Time (100 chars) |
|-----------|------------------|
| Encryption | 0.0018s ⚡ |
| Decryption | 0.0014s ⚡ |
| Known-Plaintext Attack | 0.0121s 🎯 |
---

## 🎭 The "Oh No" Moment

![Math Fail](https://media.giphy.com/media/3o7aCTPPm4OHfRLSH6/giphy.gif)

> *When you realize your fancy two-layer cipher breaks in 0.008 seconds with known plaintext...*

---

## 👥 Dream Team

**CR-22002:** Anum Mateen *(Lead)*  
**CR-22019:** Syeda Alishba Liaquat  

**Course:** CT-486 Network and Information Security  
**Instructor:** *Miss Saadia Arshad*  
**University:** NED University of Engineering & Technology

---

## 🎨 Project Highlights

| Process | Flow |
|---------|------|
| 🔒 **Encryption** | Playfair → Hill → Ciphertext |
| 🔓 **Decryption** | Hill⁻¹ → Playfair⁻¹ → Plaintext |
| 💥 **Attack** | Known plaintext → Recover Hill → Break everything |

---

## 📈 Security Report Card

| Attack Type | Grade | Notes |
|-------------|-------|-------|
| Frequency Analysis | A- | Hill does good diffusion |
| Known-Plaintext | F | Math says no 😅 |
| Overall | C+ | Educational success! |
---

## 🚨 Pro Tip

> *"Don't use this for your actual secrets. Unless you want the enemy to read your diary."* 📖

---

**⭐ Star this repo if you appreciate the struggle of making (and breaking) ciphers!**

*Because sometimes the journey of breaking your own code teaches more than building it.* 🧠

![Success](https://media.giphy.com/media/3o7abGQa0aRsohveX6/giphy.gif)

**Built with Python, NumPy, and copious amounts of cryptographic regret.**
