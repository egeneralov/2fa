# 2fa

Fill `${HOME}/.2faconfig.yaml` like:

```yaml
- issuer: CloudFlare
  secret: qwertyuiop

- secret: qwertyuiop
  issuer: GitHub
```

And use like `2fa GitHub`
