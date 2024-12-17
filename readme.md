# Client Trace

**Client Trace** is a lightweight and efficient npm package for generating a unique identifier for user identification in HTTP requests. It leverages request headers, socket data, and optional DNS lookups for enhanced accuracy and adaptability. This package is ideal for tracking users or devices in both server-side and client-side environments.

---

## Features

- **Accurate Identification**: Combines HTTP headers and socket information to generate a unique ID.
- **Force Mode**: A third parameter allows forcing DNS lookups to retrieve the user's IP address.
- **Lightweight and Simple**: Easy to integrate into any Node.js application.
- **Customizable**: Works with both server and client-side HTTP requests.

---

## Installation

Install the package using npm:

```bash
npm install client-trace
```

---

## Usage

### Basic Example

Here's an example of how to use **Client Trace** in a Node.js application:

```javascript
const { uniqueUserId } = require("client-trace");

// Example HTTP request data
const headers = {
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "x-forwarded-for": "203.0.113.195",
  "sec-ch-ua-platform": '"Windows"',
};
const socket = {
  remoteAddress: "203.0.113.1",
};

// Generate a unique user ID
const uniqueId = await uniqueUserId(headers, socket);

console.log("Unique ID:", uniqueId);
```

### With Force Mode

To enforce DNS lookups for IP resolution, pass `true` as the third parameter:

```javascript
const uniqueId = await uniqueUserId(headers, socket, true);

console.log("Unique ID:", uniqueId);
```

---

## API

### `uniqueUserId(headers, socket, force)`

#### Parameters:

1. **`headers`** _(Object, Required)_:

   - The request headers sent by the user. Must include common headers like `user-agent`, `x-forwarded-for`, etc.

2. **`socket`** _(Object, Required)_:

   - The socket object of the HTTP request. Must include `remoteAddress` for identifying the client IP.

3. **`force`** _(Boolean, Optional)_:
   - If `true`, the function will attempt to resolve the IP using DNS servers, even if it’s already available in headers or socket.

#### Returns:

An object containing the following properties:

- **`uniqueId`**: The generated unique identifier.

---

## Example Output

```javascript
"0d7c44c95d89d795b54dfa381ebbd2cc42635fd6383f6e28ddace29bf771d3d6";
```

---

## Error Handling

If the function encounters an error (e.g., invalid headers, DNS failure), it will log the error and return `undefined`.

---

## Use Cases

1. **User Tracing**: Generate unique IDs for identifying users across sessions or devices.
2. **Security**: Enhance logging for security and fraud detection.
3. **Analytics**: Trace devices or browsers accessing your application.

---

### ⚠️ **Note on Version 1.0.0**

This is the **first version** of the library, and there are known limitations:

- The library may generate the **same unique ID** for devices accessing the application over the **same IP address** or **network connection**.
- This behavior occurs due to the current logic relying on headers, IP, and socket information, which can be identical for users on shared networks or devices.

I am actively working to enhance the ID generation logic in future versions to address these limitations. Contributions, feedback, and suggestions are welcome!

---

## Contributions

Feel free to contribute to **Client Trace** by creating issues or submitting pull requests on the [GitHub repository](https://github.com/deepsingh245/client-trace).
