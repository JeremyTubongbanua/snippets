# Claude Stuff

```bash
claude mcp add serena -- uvx --from git+https://github.com/oraios/serena serena start-mcp-server --context ide-assistant --project $(pwd)
```

```bash
claude mcp add playwright npx @playwright/mcp@latest
```

```
#!/bin/bash
claude mcp add serena -- uvx --from git+https://github.com/oraios/serena serena
start-mcp-server --context ide-assistant --project $(pwd)
claude mcp add playwright npx @playwright/mcp@latest
claude mcp add at_mcp ~/GitHub/at_mcp
```
