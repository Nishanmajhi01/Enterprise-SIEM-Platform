# Frontend access from additional computers

The backend intentionally accepts browser requests only from explicitly trusted frontend origins.

For a Vite frontend running on the SIEM host at `http://192.168.1.50:5173`, add the following to the backend service environment:

```env
CORS_ALLOWED_ORIGINS=http://192.168.1.50:5173
```

Multiple trusted origins can be separated by commas. The existing localhost and 127.0.0.1 port 5173 origins remain allowed.

Restart the backend service after changing its environment. The frontend must also be reachable from the other computer (for Vite, bind its dev server to a LAN interface only on a trusted network). CORS does not replace authentication, workspace authorization, TLS, or network firewall rules.

Do not use `*` or automatically allow arbitrary browser origins on a security operations console.
