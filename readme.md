## 🔐 How to Secure Another Microservice

This authentication service is **fully independent** and **reusable**.  
It **must not be modified** when integrating with other services.

---

### 🔁 Authentication Flow

- 🔑 Client authenticates using this service
- 🪪 JWT token is issued
- 📤 Client sends JWT with every request
- 🛡️ Other microservices validate the token

---

### 🧩 What the Other Microservice Must Do

- 📥 Read the `Authorization` header from every request
- ✂️ Extract the JWT token
- 🔍 Validate token signature & expiry
- ✅ Allow request if token is valid
- ❌ Reject request with **401 Unauthorized** if invalid

---

### ⚙️ Security Expectations

- 🧠 Stateless architecture (no sessions)
- 🚫 CSRF disabled
- 🔐 JWT-based authentication only
- 🧩 Token validation before controller execution

---

### 👥 Role & Access Control

- 🏷️ Extract roles from JWT claims
- 🔒 Protect endpoints using roles
- 🎯 Keep authorization logic local to the service

---

### 🚫 Important Rules

- ❌ Do NOT modify this authentication service
- ❌ Do NOT re-authenticate users
- ❌ Do NOT store sessions
- ✅ Trust only JWTs issued by this service

---

### ✅ Final Result

- 🔒 Centralized authentication
- 🧩 Independent microservices
- 📈 Scalable system