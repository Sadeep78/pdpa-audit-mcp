const express = require('express');
const app = express();

app.post('/api/register', (req, res) => {
    // Insecure logging of user personal data and sensitive NIC
    console.log("Processing registration for user:", req.body.nic, req.body.email);
    console.info(`Contact phone logged: ${req.body.phone}`);
    res.json({ status: "ok" });
});
