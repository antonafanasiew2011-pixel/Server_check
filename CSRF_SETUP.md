# CSRF Protection Setup

## Current Status
CSRF protection is currently **disabled** for development purposes to avoid blocking legitimate requests.

## To Enable CSRF Protection

### 1. Uncomment CSRF Middleware
In `app/main.py`, uncomment this line:
```python
app.add_middleware(CSRFMiddleware, secret_key=settings.secret_key)
```

### 2. Enable CSRF Token Generation
In `app/csrf.py`, uncomment the blocking line:
```python
# Change this:
# raise HTTPException(status_code=403, detail="Invalid CSRF token")

# To this:
raise HTTPException(status_code=403, detail="Invalid CSRF token")
```

### 3. Add CSRF Tokens to Forms
In `templates/base.html`, restore the CSRF token generation:
```javascript
// Add CSRF token to all forms
const forms = document.querySelectorAll('form');
forms.forEach(form => {
  if (!form.querySelector('input[name="csrf_token"]')) {
    const csrfInput = document.createElement('input');
    csrfInput.type = 'hidden';
    csrfInput.name = 'csrf_token';
    csrfInput.value = '{{ request.session.get("csrf_token", "") }}';
    form.appendChild(csrfInput);
  }
});
```

### 4. Add CSRF Token to Templates
For each form template, add:
```html
<input type="hidden" name="csrf_token" value="{{ request.session.get('csrf_token', '') }}">
```

## Security Benefits
- Prevents Cross-Site Request Forgery attacks
- Ensures forms are submitted from legitimate sources
- Protects against malicious form submissions

## Development vs Production
- **Development**: CSRF disabled for easier testing
- **Production**: CSRF should be enabled for security
