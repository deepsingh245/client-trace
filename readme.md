### **README for `client-trace`**

---

# **client-trace**

`client-trace` is a lightweight and flexible NPM package for generating unique IDs to identify users based on their HTTP request data. This package extracts essential information such as headers, IP addresses, and device attributes to produce a reliable unique identifier, making it ideal for tracking users across client-server interactions.

---

## **Features**

- **Automatic User Identification**: Combines headers, device attributes, and IPs for accurate user identification.
- **Lightweight**: Minimal dependencies and straightforward implementation.
- **Secure Hashing**: Uses cryptographic methods to hash identifiers securely.
- **Cross-Platform**: Works for both server-side and client-side (with Node.js environments).

---

## **Installation**

```bash
npm install client-trace
```

---

## **Usage**

### **Import the Package**

First, import the package into your Node.js project:

```javascript
const { userIdentification } = require("client-trace");
```

### **Example Usage**

Here’s how you can use `client-trace` to generate a unique user ID based on an HTTP request:

```javascript
const express = require("express");
const { userIdentification } = require("client-trace");

const app = express();

app.use(express.json());

app.post("/generate-id", async (req, res) => {
  try {
    // Extract headers from the incoming request
    const headers = req.headers;

    // Generate a unique ID for the user
    const uniqueId = await userIdentification(headers);

    res.status(200).json({
      success: true,
      uniqueId,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
```

### **Request Headers Example**

When sending a request to the server, include the following headers:

- `User-Agent`: For device and browser information.
- `X-Forwarded-For`: For the client’s IP address (if behind a proxy).
- Other standard HTTP headers like `sec-ch-ua-platform`, `referer`, etc.

### **Response Example**

A successful response from the endpoint might look like this:

```json
{
  "success": true,
  "uniqueId": "hashed-id-value"
}
```

---

## **API Documentation**

### **`userIdentification(headers)`**

- **Description**: Accepts HTTP request headers and generates a unique user ID.
- **Parameters**:
  - `request` (Object): The entire HTTP request object, including headers, body, and other metadata.
- **Returns**:
  - A Promise that resolves to an object containing:
    - `uniqueId` (string): A secure hashed identifier for the user.
- **Example**:

  ```javascript
  const req = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "x-forwarded-for": "203.0.113.1",
    "sec-ch-ua-platform": "Windows",
  };

  const userData = await userIdentification(req);
  console.log(userData);
  ```

---

## **Requirements**

- Node.js `>=14.x`
- Supports HTTPS request handling.

---

## **License**

This package is licensed under the MIT License. See the LICENSE file for more details.

---

## **Contributing**

Contributions, issues, and feature requests are welcome! Feel free to fork the repository and submit a pull request.

---

## **Author**

Developed by [Deep Singh](https://github.com/deepsingh245)
