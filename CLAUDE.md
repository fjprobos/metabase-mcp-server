# metabase-mcp-server

Servidor MCP (Model Context Protocol) en TypeScript que expone 80+ herramientas para
operar Metabase (dashboards, cards/preguntas, bases de datos, tablas) desde asistentes
de IA como Claude. Es un fork de madeofclay sobre el paquete open-source
`CognitionAI/metabase-mcp-server`, con un gateway OAuth agregado (`src/oauth-gateway.ts`)
para que clientes MCP remotos (ej. Claude.ai) se autentiquen contra una instancia
Metabase (por defecto `analytics.clay.cl`) sin compartir credenciales directamente.

## Qué hace

1. Al arrancar, `src/server.ts` carga configuración (`METABASE_URL` + API key o
   usuario/password) y crea un `MetabaseClient` (modo stdio) o espera credenciales
   por request (modo HTTP Stream, vía headers `x-metabase-*`).
2. Registra las herramientas MCP (`addDashboardTools`, `addDatabaseTools`,
   `addCardTools`, `addTableTools`, `addAdditionalTools`) sobre `FastMCP`, filtradas
   según el modo (`--essential` por defecto, `--all`, `--read`, `--write`).
3. Cada tool invoca `MetabaseClient` (`src/client/metabase-client.ts`), que llama a la
   REST API de Metabase (axios) usando la sesión/API key resuelta.
4. En modo HTTP Stream, el servidor escucha en `/mcp` (puerto 8011 por defecto).
5. Opcionalmente, `src/oauth-gateway.ts` corre un servidor Express separado (puerto
   8080 por defecto) que implementa Authorization Code + PKCE: muestra un formulario
   para ingresar credenciales Metabase, emite un JWT propio, y proxea las llamadas al
   servidor HTTP Stream inyectando los headers `x-metabase-*`.

## Estructura de carpetas

```
src/
  server.ts              # entrypoint MCP (stdio y HTTP Stream), registro de tools y filtrado
  oauth-gateway.ts        # gateway Express OAuth2 (Authorization Code + PKCE) para clientes como Claude.ai
  auth.ts                 # resolución de credenciales por request (headers x-metabase-*) en modo HTTP
  client/
    metabase-client.ts    # cliente HTTP hacia la REST API de Metabase (axios)
  tools/
    dashboard-tools.ts    # CRUD de dashboards, cards en dashboard, sharing/embedding
    card-tools.ts         # CRUD de cards/preguntas, ejecución de queries, pivot, public links
    database-tools.ts     # gestión de conexiones de bases de datos en Metabase, schema sync
    table-tools.ts        # metadata de tablas/campos, operaciones de datos (incl. replace CSV)
    additional-tools.ts   # colecciones, búsqueda, usuarios, actividad, playground links
    tool-filters.ts        # parseo de flags --essential/--all/--read/--write
  utils/config.ts         # carga y valida METABASE_URL / credenciales desde env vars
  types/                  # tipos de config y errores
docs/spec-google-sso-auth.md  # spec (no implementada del todo) para soportar sesión de Google SSO
Dockerfile / docker-compose.yml / docker-run.sh  # empaquetado para self-host vía Docker
smithery.yaml             # manifiesto para publicar en el registro Smithery (MCP)
.github/workflows/publish.yml  # única CI/CD: publica el paquete a npm en push a main
tests/                    # vitest (auth, config, metabase-client, oauth-gateway, tool-filters)
```

## Dependencias de infraestructura

| Recurso | Motor / detalle | Ambiente |
|---|---|---|
| Metabase (externo) | Instancia Metabase de Clay (ej. `analytics.clay.cl`), consumida vía REST API | prod y develop (según `METABASE_URL` / header `x-metabase-url`) |
| Registro npm | `@cognitionai/metabase-mcp-server` (scope del proyecto upstream, no `madeofclay`) | prod (publicación en cada push a `main`) |

No hay bases de datos propias, colas SQS/SNS, buckets S3, tablas DynamoDB, Lambdas,
clusters EKS ni Terraform en este repo. El único estado en memoria es un `Map` de
códigos de autorización pendientes dentro de `oauth-gateway.ts` (TTL 10 minutos, se
pierde al reiniciar el proceso).

**Nota de levantamiento:** este repo estaba pre-clasificado como "con infraestructura
real desplegada", pero no se encontró Terraform, manifiestos K8s, SAM ni serverless.yml
en el árbol. Si el gateway OAuth corre en producción para Clay, la infraestructura que
lo aloja (contenedor, host, dominio público) vive fuera de este repositorio — confirmar
con el equipo dueño en la revisión 1 a 1.

## Ejecución local

```bash
npm ci
export METABASE_URL=https://your-metabase-instance.com
export METABASE_API_KEY=your_metabase_api_key   # o METABASE_USERNAME + METABASE_PASSWORD

npm run build        # compila TS a build/ y copia a dist/
npm start            # modo stdio (proceso local)

# Modo HTTP Stream compartido:
MCP_TRANSPORT=http PORT=8011 node dist/server.js

# Gateway OAuth (proxea al HTTP Stream de arriba):
npm run start:gateway   # o: GATEWAY_PORT=8080 MCP_UPSTREAM=http://localhost:8011 node dist/oauth-gateway.js

# Tests
npm test
npm run test:watch

# Docker
docker-compose up
# o
./docker-run.sh
```

## Deploy

El único mecanismo de CI/CD real en el repo es `.github/workflows/publish.yml`:
en cada push a `main` (rama default), compila el proyecto, compara la versión de
`package.json` contra la versión publicada en npm, y si cambió, ejecuta `npm publish`
(usando el secret `COGNITION_NPM_TOKEN`) y crea un tag `vX.Y.Z`. No hay despliegue a
AWS, ECS, EKS ni Lambda gestionado desde este repo. Usar `[skip ci]` en el mensaje de
commit para saltar este workflow cuando corresponda.

El paquete Docker (`Dockerfile`) permite self-host, pero no hay evidencia en el repo de
dónde corre en producción para Clay — si se detecta un despliegue real (ej. un host o
servicio externo sirviendo el gateway OAuth), documentarlo aquí y en `repo_structure.yaml`.

**Gotcha detectado (no corregido en este levantamiento):** el `CMD` del `Dockerfile`
ejecuta `node dist/index.js`, pero el build y `package.json.main` generan
`dist/server.js` — el contenedor tal como está definido probablemente falla al iniciar.
