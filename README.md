# LABORATORIO 1 — Manual Doctoral Completo
## Sanitización, Privacidad Diferencial y Cifrado Híbrido de Corpus Documental bajo LOPDP-EC

**Programa:** Maestría / Doctorado en Ciberseguridad Avanzada
**Duración estimada:** 16 horas académicas (4 sesiones de 4 h)
**Modalidad:** Laboratorio práctico individual con defensa oral
**Prerrequisito teórico:** Criptografía aplicada, fundamentos de ML, derecho digital

---

## ÍNDICE

1. Marco teórico y normativo
2. Caso de estudio y modelado de amenazas
3. Arquitectura del sistema (vista C4)
4. Prerrequisitos de hardware, software y conocimiento
5. Módulo A — Provisionamiento de infraestructura
6. Módulo B — Generación del corpus de prueba
7. Módulo C — Extracción de texto y pipeline de ingesta
8. Módulo D — Recognizers locales ecuatorianos
9. Módulo E — Análisis y anonimización con Presidio
10. Módulo F — Entrenamiento diferencialmente privado con Opacus
11. Módulo G — Cifrado híbrido con age y custodia en Vault
12. Módulo H — Replicación y verificación criptográfica
13. Módulo I — Auditoría de fuga residual
14. Troubleshooting consolidado
15. Ejercicios avanzados y extensiones doctorales
16. Rúbrica de evaluación
17. Referencias normativas y técnicas

---

## 1. MARCO TEÓRICO Y NORMATIVO

### 1.1 Fundamento jurídico ecuatoriano

La **Ley Orgánica de Protección de Datos Personales (LOPDP)**, publicada en el Registro Oficial Suplemento No. 459 del 26 de mayo de 2021, y su **Reglamento General** (Decreto Ejecutivo No. 904 de 2023), constituyen el marco vinculante. Los artículos relevantes para este laboratorio son:

- **Art. 4** — Principios de licitud, lealtad, transparencia, finalidad, pertinencia, minimización, exactitud, conservación, seguridad, responsabilidad demostrada y proactiva.
- **Art. 10** — Tratamiento de datos sensibles (salud, biométricos, ideología) requiere consentimiento explícito o habilitación legal expresa.
- **Art. 38** — Registro de actividades de tratamiento como obligación del responsable.
- **Art. 41** — Evaluación de impacto relativa a la protección de datos personales (EIPD) cuando el tratamiento implique alto riesgo.
- **Art. 42** — Medidas técnicas y organizativas: cifrado, seudonimización, control de acceso, integridad y resiliencia.
- **Art. 48** — Notificación de brecha en 72 horas a la Autoridad de Protección de Datos.

### 1.2 Marcos técnicos de referencia

- **ISO/IEC 27701:2019** — Extensión de gestión de información de privacidad sobre ISO/IEC 27001.
- **ISO/IEC 20889:2018** — Terminología de des-identificación: anonimización, seudonimización, agregación, perturbación.
- **NIST SP 800-188** — *De-Identifying Government Datasets*. Define el ciclo: caracterización → selección de técnica → aplicación → evaluación de riesgo.
- **NIST SP 800-122** — Guía para la protección de PII (definición operativa de PII directa e indirecta).
- **NIST SP 800-57 Part 1 Rev. 5** — Recomendaciones de gestión de claves criptográficas.

### 1.3 Conceptos formales que debe dominar el estudiante

**Privacidad diferencial (ε,δ)** — Un mecanismo aleatorizado M satisface (ε,δ)-DP si para todo par de bases de datos vecinas D y D' (diferentes en un registro) y todo conjunto S del rango de M:

`Pr[M(D) ∈ S] ≤ exp(ε) · Pr[M(D') ∈ S] + δ`

Interpretación operacional: ε pequeño implica que la salida del mecanismo es estadísticamente indistinguible respecto a la inclusión o exclusión de cualquier individuo particular. La convención industrial sitúa ε ∈ [0.1, 10]; valores ε ≤ 3 con δ < 1/n se consideran defensibles para datos personales sensibles.

**DP-SGD** — Variante de SGD con dos modificaciones: (i) *per-sample gradient clipping* a norma C; (ii) inyección de ruido gaussiano N(0, σ²C²I) al gradiente agregado. La composición secuencial del presupuesto se contabiliza vía el *Rényi Differential Privacy accountant*, más ajustado que la composición simple.

**Cifrado autenticado** — Garantiza confidencialidad e integridad simultáneamente. `age` usa ChaCha20-Poly1305 sobre claves derivadas X25519, cumpliendo IETF RFC 9180 (HPKE) en su variante de stream encryption.

---

## 2. CASO DE ESTUDIO Y MODELADO DE AMENAZAS

### 2.1 Contexto institucional ficticio

El **Ministerio de Salud Pública del Ecuador (MSP)** opera 23 hospitales regionales que producen, en conjunto, ~240,000 documentos anuales: oficios internos, historiales clínicos digitalizados (CDA-XML), reportes de laboratorio, recetas, autorizaciones quirúrgicas. La Subsecretaría Nacional de Vigilancia de la Salud requiere construir un clasificador automatizado de tópicos clínicos que enrute los expedientes hacia las unidades especializadas correctas (cardiología, oncología, ginecobstetricia, etc.), reduciendo tiempos de gestión administrativa.

### 2.2 Modelo de amenazas (STRIDE simplificado)

| Activo | Amenaza | Adversario | Mitigación arquitectónica |
|--------|---------|------------|--------------------------|
| Corpus en `raw-corpus` | Information Disclosure | Administrador interno deshonesto | Cifrado SSE-S3 + RBAC IAM |
| Documentos en tránsito | Eavesdropping | Atacante en red | TLS 1.3 mutuo |
| Modelo entrenado | Model Inversion / Membership Inference | Investigador adversario | DP-SGD con ε ≤ 3 |
| Claves criptográficas | Key Theft | Compromiso de host | Vault Transit Engine + HSM (en producción) |
| Logs del pipeline | Re-identificación por trazas | Auditor con acceso parcial | Hash determinístico con sal por documento |

### 2.3 Sujetos de datos y categorías PII

El corpus contiene:
- **PII directa**: nombres completos, cédulas, RUC, pasaportes, números telefónicos, correos, direcciones físicas.
- **PII indirecta (cuasi-identificadores)**: fechas de nacimiento parciales, profesión, código postal, hospital de atención.
- **Datos sensibles (Art. 4 LOPDP)**: diagnósticos CIE-10, medicación, antecedentes psiquiátricos, condición VIH, embarazo.

### 2.4 Objetivos verificables del laboratorio

Al final del laboratorio, el estudiante debe poder demostrar:

1. **O1** — Cero PII directa residual en el corpus sanitizado (verificable por regex de auditoría).
2. **O2** — Modelo de clasificación con `ε ≤ 3` y `δ ≤ 1e-5` formalmente certificado por el privacy accountant.
3. **O3** — Pérdida de utilidad (F1-score) respecto al modelo no-privado documentada y justificada.
4. **O4** — Corpus cifrado descifrable únicamente con clave custodiada en Vault bajo política RBAC.
5. **O5** — Generación de un Registro de Actividades de Tratamiento conforme al Art. 38 LOPDP.

---

## 3. ARQUITECTURA DEL SISTEMA

### 3.1 Vista de contexto (C4 nivel 1)

```
                    ┌─────────────────────┐
                    │  Subsecretaría MSP  │
                    │  (Data Consumer)    │
                    └──────────▲──────────┘
                               │ modelos + corpus sanitizado
            ┌──────────────────┴──────────────────┐
            │     PIPELINE DE PRIVACIDAD MSP      │
            │     (Sistema bajo diseño)           │
            └──────────────────▲──────────────────┘
                               │ documentos raw
            ┌──────────────────┴──────────────────┐
            │   23 Hospitales Regionales (HIS)    │
            └─────────────────────────────────────┘
```

### 3.2 Vista de contenedores (C4 nivel 2)

```
┌─────────────────────────────────────────────────────────────────────┐
│                  PIPELINE DE PRIVACIDAD                              │
│                                                                       │
│  ┌──────────┐   ┌────────┐   ┌──────────┐   ┌──────────────┐        │
│  │  MinIO   │──▶│  Tika  │──▶│ Presidio │──▶│ Anonymizer   │        │
│  │ raw-bckt │   │(extr.) │   │ Analyzer │   │ + Operators  │        │
│  └──────────┘   └────────┘   └──────────┘   └──────┬───────┘        │
│                                                     │                 │
│                                                     ▼                 │
│  ┌──────────┐   ┌──────────────┐   ┌──────────────────────┐         │
│  │  age     │◀──│  MinIO       │◀──│  Sanitized Corpus    │         │
│  │ encrypt  │   │ sanitized    │   │  (texto + metadatos) │         │
│  └────┬─────┘   └──────────────┘   └──────────────────────┘         │
│       │                                          │                    │
│       ▼                                          ▼                    │
│  ┌──────────┐                       ┌─────────────────────┐          │
│  │  Vault   │                       │  Opacus DP-SGD      │          │
│  │  KV+PKI  │                       │  Trainer (PyTorch)  │          │
│  └──────────┘                       └─────────────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Flujo de datos (secuencia)

1. Documento ingresa a `raw-corpus` cifrado en reposo con SSE-S3.
2. Worker descarga binario, lo envía a Tika.
3. Tika devuelve texto plano UTF-8 y metadatos (autor, fecha, mime).
4. Texto se envía a Presidio Analyzer; retorna lista de entidades con offsets.
5. Recognizer EC valida cédulas vía algoritmo módulo 10.
6. Anonymizer aplica matriz de operadores: replace, hash, mask, encrypt, redact.
7. Texto sanitizado se vuelca a `sanitized-corpus` con metadata de transformación.
8. Periódicamente, trainer DP-SGD consume corpus sanitizado y produce modelo.
9. Modelo y corpus se empaquetan, cifran con age y se replican al nodo secundario.
10. Vault retiene la clave privada bajo política `read-only` con TTL.

---

## 4. PRERREQUISITOS

### 4.1 Hardware mínimo

- CPU: 4 cores x86_64 (recomendado 8).
- RAM: 16 GB (recomendado 32 GB para el módulo F).
- Disco: 40 GB libres en SSD.
- GPU opcional: cualquier NVIDIA con ≥ 6 GB VRAM y CUDA 12 reduce el tiempo del módulo F de ~3 h a ~25 min.

### 4.2 Software base (Ubuntu 22.04 / 24.04 LTS)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git build-essential ca-certificates \
    python3 python3-pip python3-venv python3-dev \
    jq tree htop net-tools openssh-client

# Docker Engine + Compose v2
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker   # o cerrar sesión y reabrir

# Verificación
docker --version           # ≥ 24.0.0
docker compose version     # ≥ 2.20.0
python3 --version          # ≥ 3.10
```

### 4.3 Entorno Python aislado

```bash
# =========================
# 0. Crear y entrar al proyecto
# =========================

mkdir -p ~/lab1
cd ~/lab1


# =========================
# 1. Dependencias del sistema
# =========================

apt update

apt install -y \
  python3 \
  python3-venv \
  python3-pip \
  python-is-python3 \
  build-essential \
  libmagic1 \
  libmagic-dev


# =========================
# 2. Crear entorno virtual
# =========================

python3 -m venv .venv
source .venv/bin/activate


# =========================
# 3. Actualizar herramientas base de Python
# =========================

python -m pip install --upgrade pip setuptools wheel


# =========================
# 4. Crear requirements.txt
# =========================

cat > requirements.txt <<'EOF'
presidio-analyzer==2.2.355
presidio-anonymizer==2.2.355
spacy==3.7.5
opacus==1.5.2
torch==2.4.0
transformers==4.44.2
datasets==2.21.0
scikit-learn==1.5.1
pandas==2.2.2
requests==2.32.3
python-magic==0.4.27
faker==26.0.0
cryptography==43.0.0
hvac==2.3.0
minio==7.2.7
click==8.1.7
pyarrow==17.0.0
EOF


# =========================
# 5. Instalar dependencias Python
# =========================

python -m pip install -r requirements.txt


# =========================
# 6. Descargar modelos de spaCy
# =========================

python -m spacy download es_core_news_lg
python -m spacy download en_core_web_lg


# =========================
# 7. Verificar instalación
# =========================

python - <<'PY'
import torch
import spacy
import pandas
import faker
import presidio_analyzer
import presidio_anonymizer

print("Torch:", torch.__version__)
print("CUDA disponible:", torch.cuda.is_available())
print("spaCy:", spacy.__version__)
print("Pandas:", pandas.__version__)
print("Entorno listo.")
PY


# =========================
# 8. Ejecutar generación de corpus
# =========================
# Esto asume que existe el archivo:
# ~/lab1/scripts/gen_corpus.py

if [ -f scripts/gen_corpus.py ]; then
    python scripts/gen_corpus.py
else
    echo "[ADVERTENCIA] No existe scripts/gen_corpus.py"
    echo "Crea o copia el archivo en: ~/lab1/scripts/gen_corpus.py"
fi
```

### 4.4 Instalación de age (cifrado)

```bash
cd /tmp
curl -sLO https://github.com/FiloSottile/age/releases/download/v1.2.0/age-v1.2.0-linux-amd64.tar.gz
tar -xzf age-v1.2.0-linux-amd64.tar.gz
sudo install -m 0755 age/age /usr/local/bin/age
sudo install -m 0755 age/age-keygen /usr/local/bin/age-keygen
age --version    # debe mostrar v1.2.0
```

### 4.5 Cliente MinIO

```bash
curl -sLO https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc && sudo mv mc /usr/local/bin/
mc --version
```

### 4.6 Cliente Vault

```bash
curl -sLO https://releases.hashicorp.com/vault/1.17.3/vault_1.17.3_linux_amd64.zip
unzip vault_1.17.3_linux_amd64.zip && sudo install -m 0755 vault /usr/local/bin/
vault --version
```

---

## 5. MÓDULO A — PROVISIONAMIENTO DE INFRAESTRUCTURA

### A.1 Estructura del proyecto

```bash
cd ~/lab1
mkdir -p {data/raw,data/sanitized,data/corpus,recognizers,scripts,models,keys,logs,reports}
tree -L 2
```

Salida esperada:
```
.
├── data
│   ├── corpus
│   ├── raw
│   └── sanitized
├── keys
├── logs
├── models
├── recognizers
├── reports
├── requirements.txt
└── scripts
```

### A.2 Stack Docker Compose

Crea `~/lab1/docker-compose.yml`:

```yaml
version: "3.9"

networks:
  lab1-net:
    driver: bridge

volumes:
  minio_data:
  vault_data:

services:
  minio:
    image: minio/minio:RELEASE.2024-08-17T01-24-54Z
    container_name: lab1-minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: lab1admin
      MINIO_ROOT_PASSWORD: Lopdp2026
      # NOTA: NO usar MINIO_DEFAULT_BUCKETS — los buckets se crean manualmente
      # en A.4 porque Object Lock requiere `mc mb --with-lock` al momento de la
      # creación y no puede habilitarse retroactivamente.
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - minio_data:/data
    networks: [lab1-net]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 10s
      timeout: 5s
      retries: 5

  vault:
    image: hashicorp/vault:1.17
    container_name: lab1-vault
    cap_add: [IPC_LOCK]
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: root-token-lab1
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    ports:
      - "8200:8200"
    volumes:
      - vault_data:/vault/file
    networks: [lab1-net]

  presidio-analyzer:
    image: mcr.microsoft.com/presidio-analyzer:latest
    container_name: lab1-analyzer
    ports:
      - "5001:3000"
    networks: [lab1-net]
    environment:
      PIP_NO_CACHE_DIR: "1"

  presidio-anonymizer:
    image: mcr.microsoft.com/presidio-anonymizer:latest
    container_name: lab1-anonymizer
    ports:
      - "5002:3000"
    networks: [lab1-net]

  tika:
    image: apache/tika:2.9.2.1-full
    container_name: lab1-tika
    ports:
      - "9998:9998"
    networks: [lab1-net]
```

### A.3 Arranque y verificación

```bash
cd ~/lab1
docker compose up -d
docker compose ps
```

Cada servicio debe reportar `Up` y estado `healthy` cuando aplique. Esperar 30–60 s para que las imágenes Presidio carguen los modelos NLP.

Pruebas de humo:

```bash
# MinIO
curl -s http://localhost:9000/minio/health/live && echo "MinIO OK"

# Vault
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root-token-lab1
vault status

# Presidio Analyzer
curl -s -X POST http://localhost:5001/analyze \
  -H "Content-Type: application/json" \
  -d '{"text":"My name is John","language":"en"}' | jq

# Presidio Anonymizer
curl -s http://localhost:5002/health

# Tika
curl -s -T <(echo "Texto de prueba") http://localhost:9998/tika \
  -H "Accept: text/plain"
```

### A.4 Configuración del cliente MinIO

```bash
mc alias set lab1 http://localhost:9000 lab1admin 'Lopdp2025!Secure'
mc admin info lab1
mc ls lab1
```

#### A.4.1 Creación de buckets con la política correcta

**Punto crítico:** S3 Object Lock (replicado fielmente por MinIO) sólo puede habilitarse **en el momento de crear el bucket** mediante el flag `--with-lock`. No existe operación para activarlo retroactivamente sobre un bucket existente — esto es una restricción del modelo de datos S3, no de MinIO. Cualquier intento de aplicar `mc retention set --default` sobre un bucket creado sin Object Lock fallará con `Bucket is missing ObjectLockConfiguration`.

En consecuencia, los buckets se crean manualmente:

```bash
# raw-corpus y models: sin Object Lock (datos transitorios o reemplazables)
mc mb lab1/raw-corpus
mc mb lab1/models

# sanitized-corpus: CON Object Lock (evidencia regulatoria)
mc mb --with-lock lab1/sanitized-corpus
```

Verificación inmediata:

```bash
mc version info lab1/sanitized-corpus
# salida esperada: "lab1/sanitized-corpus versioning is enabled"
```

Object Lock implica versionado obligatorio; MinIO lo activa automáticamente al usar `--with-lock`, por lo que no es necesario invocar `mc version enable` por separado.

#### A.4.2 Política de retención por defecto

```bash
mc retention set --default GOVERNANCE 30d lab1/sanitized-corpus
mc retention info --default lab1/sanitized-corpus
```

Salida esperada:
```
Default retention mode  : GOVERNANCE
Default retention until : 30d
```

#### A.4.3 Decisión arquitectónica: GOVERNANCE vs COMPLIANCE

MinIO ofrece dos modos de retención. El estudiante debe poder defender oralmente la elección:

| Modo | Comportamiento | Caso de uso |
|------|----------------|-------------|
| **GOVERNANCE** | Usuarios con el permiso `s3:BypassGovernanceRetention` pueden eliminar antes del vencimiento. | Cumplimiento ordinario con excepciones controladas (corrección de error operacional autorizada por el DPO). |
| **COMPLIANCE** | Nadie, ni el root, puede eliminar hasta el vencimiento. Inmutabilidad absoluta. | Evidencia forense bajo cadena de custodia judicial. |

Para el laboratorio se selecciona **GOVERNANCE** porque el **Art. 12 de la LOPDP** consagra el derecho de supresión ("derecho al olvido"): el responsable del tratamiento debe poder eliminar datos de un titular que ejerza ese derecho. COMPLIANCE entraría en conflicto directo con esa obligación legal y bloquearía al MSP frente a una solicitud legítima de un paciente. Se prioriza el cumplimiento sustantivo (Art. 12) sobre la inmutabilidad técnica absoluta, conservando la protección contra borrado accidental o malicioso vía RBAC sobre el permiso `BypassGovernanceRetention`.

#### A.4.4 Verificación funcional de la inmutabilidad

Esta sección documenta el comportamiento real de MinIO Object Lock, incluyendo los tres errores operacionales que el estudiante encontrará en la práctica y cómo resolverlos.

---

##### Conceptos previos obligatorios

Antes de ejecutar la prueba hay que tener claros tres comportamientos de S3/MinIO que no son intuitivos:

| Operación | Resultado en bucket versionado con Object Lock | Error de lectura típica |
|-----------|-----------------------------------------------|------------------------|
| `mc rm objeto` | Crea un *delete marker*. La versión original queda intacta. El comando **reporta éxito** aunque no borró nada. | "WORM no funciona" |
| `mc rm --version-id VID` sin retención en el objeto | Borra la versión. **Reporta éxito** porque no hay retención que bloquee. | "WORM no funciona" |
| `mc rm --version-id VID` **con** retención activa | Falla con `Object is WORM protected`. Este es el comportamiento buscado. | — |
| `mc retention info objeto` cuando la versión actual es un delete marker | Reporta `The specified key does not exist` aunque el objeto real exista en versiones anteriores. | "El objeto no existe" |

La prueba de inmutabilidad **sólo puede tener éxito** si se cumplen dos condiciones: (a) el objeto tiene retención explícita aplicada, y (b) se intenta borrar la versión específica por su `version-id`.

---

##### Limpieza total de intentos previos

Si ya ejecutaste comandos sobre `test-lock.txt` en iteraciones anteriores, el objeto puede estar en un estado inconsistente: varias versiones `PUT` antiguas sin retención, y uno o más delete markers encima que hacen que `mc retention info` reporte `The specified key does not exist`.

Limpia todo antes de empezar:

```bash
# Listar todas las versiones para entender el estado actual
mc ls --versions lab1/sanitized-corpus/test-lock.txt

# Borrar TODAS las versiones (delete markers y objetos sin retención)
# --bypass-governance cubre el caso de versiones que sí quedaron bajo WORM
mc ls --versions --json lab1/sanitized-corpus/test-lock.txt 2>/dev/null \
  | jq -r '.versionId' \
  | while read V; do
      echo "Eliminando versión: $V"
      mc rm --version-id "$V" --bypass-governance \
        lab1/sanitized-corpus/test-lock.txt 2>&1
    done

# Confirmar que no queda nada
mc ls --versions lab1/sanitized-corpus/test-lock.txt
# Debe retornar vacío
```

Si algún `mc rm` de la limpieza reporta `Object is WORM protected` y **falla** incluso con `--bypass-governance`, significa que esa versión quedó bajo retención COMPLIANCE (inmutable absoluta). En el laboratorio usamos GOVERNANCE, así que esto no debería ocurrir; si ocurre indica que el bucket fue recreado con modo incorrecto.

---

##### Procedimiento de prueba correcto (desde estado limpio)

**Paso 1 — Verificar versiones de los componentes.** Algunas versiones antiguas de `mc` tienen regresiones en Object Lock.

```bash
mc --version                                       # mínimo: RELEASE.2024-*
docker exec lab1-minio minio --version             # versión del servidor
mc version info lab1/sanitized-corpus              # debe decir: versioning is enabled
mc retention info --default lab1/sanitized-corpus  # debe mostrar GOVERNANCE / 30d
```

Si `mc version info` no muestra `versioning is enabled`, el bucket no tiene Object Lock y debe recrearse siguiendo A.4.5. Si la retención por defecto no aparece, ejecútala ahora: `mc retention set --default GOVERNANCE 30d lab1/sanitized-corpus`.

**Paso 2 — Subir el objeto.**

```bash
echo "documento WORM $(date -u +%FT%TZ)" > /tmp/test-lock.txt
mc cp /tmp/test-lock.txt lab1/sanitized-corpus/test-lock.txt
```

**Paso 3 — Capturar el `version-id` inmediatamente tras la subida.**

```bash
mc ls --versions --json lab1/sanitized-corpus/test-lock.txt | jq
```

Inspecciona la salida — el campo clave es `isDeleteMarker`. El filtro correcto usa ese campo, NO `.type=="PUT"`:

```bash
VID=$(mc ls --versions --json lab1/sanitized-corpus/test-lock.txt \
      | jq -r 'select(.isDeleteMarker==false) | .versionId' \
      | head -1)
echo "VID = '$VID'"
```

Si `$VID` está vacío o vale `null`, no continúes:

```bash
if [ -z "$VID" ] || [ "$VID" = "null" ]; then
    echo "⚠ VID vacío — no ejecutes el Paso 4"
    echo "  Verifica: mc ls --versions lab1/sanitized-corpus/test-lock.txt"
else
    echo "✓ VID válido: $VID"
fi
```

> **Por qué no usamos `exit 1` aquí.** `exit` en una terminal interactiva cierra la sesión completa. El bloque usa `if/else` para advertir sin cerrar. Si incorporas este código en un script `.sh` que se invoca con `bash script.sh`, allí sí puedes usar `exit 1` porque termina el proceso hijo, no tu sesión.

**Paso 4 — Aplicar retención EXPLÍCITA al objeto por su `version-id`.**

La retención por defecto del bucket es frágil: según la versión de `mc` y del servidor MinIO, puede no aplicarse automáticamente al `PUT`. La práctica robusta — alineada con **NIST SP 800-188 §4.3** sobre controles verificables — es ordenar la retención explícitamente, no inferirla:

```bash
mc retention set --version-id "$VID" GOVERNANCE 30d \
  lab1/sanitized-corpus/test-lock.txt
```

**Paso 5 — Verificar que la retención quedó aplicada.**

```bash
mc retention info --version-id "$VID" lab1/sanitized-corpus/test-lock.txt
```

Salida esperada:
```
MODE        : GOVERNANCE
TILL        : <fecha actual + 30 días>
```

Si la salida es `The specified key does not exist` — el objeto fue borrado lógicamente por un delete marker de una iteración anterior. Ejecuta la **limpieza total** del inicio de esta sección y vuelve al Paso 2.

Si la salida dice `No retention configuration found` — la retención del Paso 4 no se aplicó. Verifica versiones (`mc --version`) y reintenta con el flag `--version-id` explícito.

**Paso 6 — Intento de borrado de la versión protegida (debe fallar).**

```bash
mc rm --version-id "$VID" lab1/sanitized-corpus/test-lock.txt
```

Salida esperada:
```
mc: <ERROR> Failed to remove `lab1/sanitized-corpus/test-lock.txt`.
Object is WORM protected and cannot be overwritten or deleted until <fecha>.
```

**WORM está activo.** Si el comando borra el objeto sin error, la retención del Paso 4 no se aplicó correctamente — revisar Paso 5.

---

##### Paso 7 (contraste pedagógico) — comportamiento del delete marker

```bash
# Borrado sin --version-id: crea delete marker, NO borra el objeto real
mc rm lab1/sanitized-corpus/test-lock.txt

# El objeto desaparece del listado normal
mc ls lab1/sanitized-corpus/ | grep test-lock || echo "no visible en listado normal"

# Pero las versiones siguen intactas
mc ls --versions lab1/sanitized-corpus/test-lock.txt
```

El último comando muestra la versión `PUT` original (bajo WORM) y el nuevo delete marker `DEL` encima.

##### Paso 8 — Restaurar eliminando el delete marker

```bash
DEL_VID=$(mc ls --versions --json lab1/sanitized-corpus/test-lock.txt \
          | jq -r 'select(.isDeleteMarker==true) | .versionId' \
          | head -1)
mc rm --version-id "$DEL_VID" lab1/sanitized-corpus/test-lock.txt
mc ls lab1/sanitized-corpus/ | grep test-lock   # vuelve a ser visible
```

Los delete markers no están bajo WORM, por lo que se eliminan libremente.

##### Paso 9 — Borrado autorizado por el DPO (derecho de supresión Art. 12 LOPDP)

```bash
mc rm --version-id "$VID" --bypass-governance lab1/sanitized-corpus/test-lock.txt
```

Este es el único camino para eliminar un objeto bajo retención GOVERNANCE. Debe quedar registrado en el log de auditoría del responsable del tratamiento.

---

**Conclusión académica.** La cadena de pruebas demuestra que:
1. WORM bloquea el borrado de versiones con retención activa (Paso 6).
2. La retención por defecto del bucket es frágil — la práctica segura es retención explícita por versión (Paso 4).
3. Los delete markers son una capa de visibilidad, no de protección (Paso 7).
4. GOVERNANCE permite excepciones autorizadas compatibles con el Art. 12 LOPDP (Paso 9).
5. `mc retention info` sin `--version-id` falla si la versión actual es un delete marker — siempre usar `--version-id` para diagnóstico preciso (Paso 5).

#### A.4.5 Procedimiento de recuperación ante error

Si en una ejecución previa creaste el bucket sin `--with-lock`, no hay forma de habilitarlo retroactivamente. El procedimiento correcto es:

```bash
# 1. Respaldar contenido (si existe)
mkdir -p ~/lab1/backup_sanitized
mc cp --recursive lab1/sanitized-corpus/ ~/lab1/backup_sanitized/ 2>/dev/null || true

# 2. Eliminar el bucket defectuoso
mc rb --force lab1/sanitized-corpus

# 3. Recrear con Object Lock
mc mb --with-lock lab1/sanitized-corpus
mc retention set --default GOVERNANCE 30d lab1/sanitized-corpus

# 4. Restaurar datos
mc cp --recursive ~/lab1/backup_sanitized/ lab1/sanitized-corpus/ 2>/dev/null || true
```

Este es un error operacional común y debe documentarse en el informe técnico como hallazgo del estudiante.

### A.5 Configuración inicial de Vault

```bash
# Habilitar KV v2
vault secrets enable -version=2 -path=secret kv

# Habilitar Transit Engine (cifrado como servicio)
vault secrets enable transit

# Crear llave maestra para cifrado de buckets
vault write -f transit/keys/lab1-corpus-master

# Habilitar motor PKI para emitir certificados internos
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
vault write -field=certificate pki/root/generate/internal \
    common_name="lab1-msp-ca" ttl=87600h > keys/ca.crt

# Política RBAC: solo lectura de clave age
cat > /tmp/age-reader.hcl <<'EOF'
path "secret/data/lab1/age-key" {
  capabilities = ["read"]
}
EOF
vault policy write age-reader /tmp/age-reader.hcl

# Token con TTL 24h para el rol "data-scientist"
vault token create -policy=age-reader -ttl=24h -display-name=data-scientist
```

Guarda el token emitido — se usará en el Módulo G.

### A.6 Checkpoint del Módulo A

Verifica con `~/lab1/scripts/check_a.sh`:

```bash
#!/usr/bin/env bash
set -e
echo "== Checkpoint Módulo A =="
docker compose ps --format json | jq -r '.[] | "\(.Service)\t\(.State)"'
mc ls lab1 | grep -q raw-corpus && echo "✓ bucket raw-corpus"
mc ls lab1 | grep -q sanitized-corpus && echo "✓ bucket sanitized-corpus"
vault read transit/keys/lab1-corpus-master >/dev/null && echo "✓ transit key creada"
echo "Módulo A: OK"
```

```bash
chmod +x ~/lab1/scripts/check_a.sh && ~/lab1/scripts/check_a.sh
```

---

## 6. MÓDULO B — GENERACIÓN DEL CORPUS DE PRUEBA

Por razones éticas y legales, no se trabaja con datos reales. Se genera un corpus sintético con estructura y vocabulario realista usando Faker localizado a `es_EC` (lo más cercano disponible es `es_MX` con sustituciones).

### B.1 Generador de documentos clínicos

Crea `~/lab1/scripts/gen_corpus.py`:

```python
#!/usr/bin/env python3
"""
Generador de corpus clínico sintético para Lab 1.
Produce 500 documentos en data/corpus/ con PII embebida.
Etiquetas para clasificación: cardiologia, neurologia, ginecobstetricia, traumatologia.
"""
import os, random, json
from pathlib import Path
from faker import Faker

fake = Faker("es_MX")
Faker.seed(42)
random.seed(42)

CORPUS_DIR = Path(__file__).parent.parent / "data" / "corpus"
CORPUS_DIR.mkdir(parents=True, exist_ok=True)

CATEGORIAS = {
    "cardiologia": [
        "hipertensión arterial estadio II", "fibrilación auricular paroxística",
        "insuficiencia cardíaca con fracción de eyección reducida",
        "cardiopatía isquémica crónica", "estenosis aórtica moderada"
    ],
    "neurologia": [
        "cefalea tensional crónica", "epilepsia focal del lóbulo temporal",
        "enfermedad cerebrovascular isquémica subaguda",
        "esclerosis múltiple recurrente-remitente", "neuropatía diabética distal"
    ],
    "ginecobstetricia": [
        "embarazo de 32 semanas con preeclampsia leve",
        "miomatosis uterina sintomática", "control prenatal del tercer trimestre",
        "menopausia precoz", "endometriosis pélvica grado III"
    ],
    "traumatologia": [
        "fractura cerrada de tibia y peroné", "lesión meniscal medial de rodilla",
        "esguince cervical post-accidente vehicular",
        "luxación recidivante de hombro", "fractura de cadera por caída"
    ],
}

def cedula_valida():
    """Genera una cédula ecuatoriana sintética que pasa el checksum módulo 10."""
    provincia = random.randint(1, 24)
    digitos = [int(d) for d in f"{provincia:02d}"] + [random.randint(0,9) for _ in range(7)]
    coef = [2,1,2,1,2,1,2,1,2]
    total = sum((d*c - 9 if d*c >= 10 else d*c) for d,c in zip(digitos, coef))
    verificador = (10 - (total % 10)) % 10
    return "".join(str(d) for d in digitos) + str(verificador)

def documento_clinico(categoria, idx):
    nombre = fake.name()
    ced = cedula_valida()
    edad = random.randint(18, 88)
    telefono = f"09{random.randint(10000000, 99999999)}"
    email = f"{nombre.lower().split()[0]}.{random.randint(100,999)}@correo.gob.ec"
    direccion = fake.address().replace("\n", ", ")
    diagnostico = random.choice(CATEGORIAS[categoria])
    medico = "Dr. " + fake.name()
    fecha = fake.date_between(start_date="-2y", end_date="today")
    hospital = random.choice([
        "Hospital de Especialidades Eugenio Espejo",
        "Hospital Carlos Andrade Marín",
        "Hospital Vicente Corral Moscoso",
        "Hospital Teodoro Maldonado Carbo",
    ])

    texto = f"""MINISTERIO DE SALUD PÚBLICA DEL ECUADOR
{hospital}

OFICIO DE REFERENCIA No. MSP-{categoria.upper()}-{idx:06d}
Fecha: {fecha.strftime('%d de %B de %Y').lower()}

DATOS DEL PACIENTE
Nombre: {nombre}
Cédula de identidad: {ced}
Edad: {edad} años
Domicilio: {direccion}
Teléfono de contacto: {telefono}
Correo electrónico: {email}

ANTECEDENTES CLÍNICOS
El paciente acude a esta unidad presentando cuadro clínico compatible con
{diagnostico}. Refiere evolución de {random.randint(1,12)} meses con sintomatología
{random.choice(['progresiva','intermitente','aguda','recurrente'])}.

VALORACIÓN
Tras evaluación física y revisión de exámenes complementarios, se confirma
el diagnóstico presuntivo. Se recomienda continuar tratamiento bajo
supervisión del servicio de {categoria}.

MEDICACIÓN ACTUAL
- {fake.word().capitalize()} {random.choice(['25','50','100','200'])} mg cada {random.choice(['8','12','24'])} horas
- Control de signos vitales

Médico tratante: {medico}
Código MSP: {random.randint(100000,999999)}

Firma electrónica: [hash documento]
"""
    return texto, categoria

if __name__ == "__main__":
    manifest = []
    for i in range(500):
        cat = random.choice(list(CATEGORIAS.keys()))
        texto, label = documento_clinico(cat, i)
        fname = f"oficio_{i:04d}_{cat}.txt"
        (CORPUS_DIR / fname).write_text(texto, encoding="utf-8")
        manifest.append({"file": fname, "label": label})

    with open(CORPUS_DIR / "manifest.jsonl", "w") as f:
        for m in manifest:
            f.write(json.dumps(m) + "\n")

    print(f"Generados 500 documentos en {CORPUS_DIR}")
    print("Distribución por categoría:")
    from collections import Counter
    c = Counter(m["label"] for m in manifest)
    for k, v in c.items():
        print(f"  {k:20} {v}")
```

Ejecuta:
```bash
cd ~/lab1
python scripts/gen_corpus.py
ls data/corpus/ | head
wc -l data/corpus/manifest.jsonl    # debe imprimir 500
```

### B.2 Subir el corpus a MinIO

```bash
mc cp --recursive data/corpus/ lab1/raw-corpus/
mc ls lab1/raw-corpus/ | wc -l    # debe ser 501 (500 + manifest)
```

### B.3 Inspección manual de un documento

```bash
cat data/corpus/oficio_0000_cardiologia.txt
```

Verifica visualmente que aparezcan: cédula de 10 dígitos, teléfono, email, dirección, nombres. Estos son los blancos que el pipeline debe neutralizar.

---

## 7. MÓDULO C — EXTRACCIÓN DE TEXTO

### C.1 Extracción individual con Tika

```bash
curl -s -T data/corpus/oficio_0000_cardiologia.txt \
  http://localhost:9998/tika -H "Accept: text/plain"
```

Para documentos PDF/DOCX reales, Tika ejecuta OCR si detecta páginas escaneadas (requiere tesseract en imagen Tika `:latest-full`).

### C.2 Wrapper Python de extracción

Crea `~/lab1/scripts/extractor.py`:

```python
import requests
from pathlib import Path

TIKA_URL = "http://localhost:9998/tika"

def extract_text(path: Path) -> str:
    with open(path, "rb") as f:
        r = requests.put(TIKA_URL, data=f, headers={"Accept": "text/plain"})
    r.raise_for_status()
    return r.text

def extract_metadata(path: Path) -> dict:
    with open(path, "rb") as f:
        r = requests.put(f"{TIKA_URL.replace('/tika','/meta')}",
                         data=f, headers={"Accept": "application/json"})
    r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    import sys
    p = Path(sys.argv[1])
    print("=== TEXTO ===")
    print(extract_text(p))
    print("=== METADATOS ===")
    import json
    print(json.dumps(extract_metadata(p), indent=2))
```

Prueba:
```bash
python scripts/extractor.py data/corpus/oficio_0000_cardiologia.txt
```

---

## 8. MÓDULO D — RECOGNIZERS LOCALES ECUATORIANOS

Presidio reconoce nativamente entidades genéricas (PERSON, LOCATION, EMAIL, PHONE_NUMBER). Para identificadores ecuatorianos hay que extenderlo.

### D.1 Recognizer de cédula con checksum módulo 10

Crea `~/lab1/recognizers/ec_cedula.py`:

```python
"""
PatternRecognizer para cédula de identidad ecuatoriana.
Algoritmo de validación: módulo 10 sobre los primeros 9 dígitos,
coeficientes [2,1,2,1,2,1,2,1,2], restando 9 si producto >= 10.
"""
from presidio_analyzer import PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts
from typing import List

class EcuadorCedulaRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern(name="ec_cedula_strict",
                regex=r"\b\d{10}\b",
                score=0.4),
    ]
    CONTEXT = ["cédula", "cedula", "identificación", "identidad",
               "documento", "ci", "c.i.", "ec"]

    def __init__(self):
        super().__init__(
            supported_entity="EC_CEDULA",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="es",
        )

    @staticmethod
    def _checksum_ok(cedula: str) -> bool:
        if len(cedula) != 10 or not cedula.isdigit():
            return False
        provincia = int(cedula[:2])
        if not (1 <= provincia <= 24) and provincia != 30:
            return False
        if int(cedula[2]) >= 6:
            return False
        coef = [2,1,2,1,2,1,2,1,2]
        total = 0
        for d, c in zip(cedula[:9], coef):
            prod = int(d) * c
            total += prod - 9 if prod >= 10 else prod
        return ((10 - (total % 10)) % 10) == int(cedula[9])

    def validate_result(self, pattern_text: str) -> bool:
        return self._checksum_ok(pattern_text)
```

### D.2 Recognizer de RUC

Crea `~/lab1/recognizers/ec_ruc.py`:

```python
"""
RUC ecuatoriano: 13 dígitos. Los 10 primeros son la cédula del titular
(persona natural) o un identificador especial (jurídica/pública); los 3
últimos son secuencial de establecimiento (001, 002, ...).
"""
from presidio_analyzer import PatternRecognizer, Pattern

class EcuadorRucRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern(name="ec_ruc", regex=r"\b\d{13}\b", score=0.45),
    ]
    CONTEXT = ["ruc", "registro único", "contribuyente", "sri"]

    def __init__(self):
        super().__init__(
            supported_entity="EC_RUC",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="es",
        )

    def validate_result(self, pattern_text: str) -> bool:
        if len(pattern_text) != 13 or not pattern_text.isdigit():
            return False
        if not pattern_text.endswith("001") and pattern_text[-3:].lstrip("0") == "":
            return False
        tercer = int(pattern_text[2])
        # Tipos válidos: 0-5 natural, 6 pública, 9 jurídica
        return tercer in {0,1,2,3,4,5,6,9}
```

### D.3 Recognizer de teléfono ecuatoriano

Crea `~/lab1/recognizers/ec_phone.py`:

```python
from presidio_analyzer import PatternRecognizer, Pattern

class EcuadorPhoneRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern(name="ec_mobile",
                regex=r"\b(?:\+593|0)9\d{8}\b", score=0.5),
        Pattern(name="ec_fixed",
                regex=r"\b(?:\+593|0)[2-7]\d{7}\b", score=0.4),
    ]
    CONTEXT = ["teléfono", "telefono", "celular", "móvil", "contacto"]

    def __init__(self):
        super().__init__(
            supported_entity="EC_PHONE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="es",
        )
```

### D.4 Pruebas unitarias de los recognizers

Crea `~/lab1/recognizers/test_recognizers.py`:

```python
import sys
sys.path.insert(0, ".")
from ec_cedula import EcuadorCedulaRecognizer
from ec_ruc import EcuadorRucRecognizer
from ec_phone import EcuadorPhoneRecognizer

# --- Cédulas ---
ced = EcuadorCedulaRecognizer()
TEST_CED = [
    ("1710034065", True),    # válida (provincia 17, Pichincha)
    ("1234567890", False),   # inválida por checksum
    ("0000000000", False),   # provincia inválida
    ("1799999999", False),   # tercer dígito >=6
]
for c, exp in TEST_CED:
    r = ced.validate_result(c)
    assert r == exp, f"FALLO cédula {c}: esperado {exp}, obtuvo {r}"
    print(f"✓ cédula {c}: {r}")

# --- RUC ---
ruc = EcuadorRucRecognizer()
assert ruc.validate_result("1710034065001")
assert not ruc.validate_result("9999999999999")
print("✓ RUC validador OK")

# --- Teléfonos ---
phone = EcuadorPhoneRecognizer()
print("✓ recognizers cargan sin errores")
```

```bash
cd ~/lab1/recognizers
python test_recognizers.py
```

---

## 9. MÓDULO E — ANÁLISIS Y ANONIMIZACIÓN

### E.1 Pipeline integrado

Crea `~/lab1/scripts/sanitize.py`:

```python
#!/usr/bin/env python3
"""
Pipeline de sanitización:
  raw-corpus → Presidio Analyzer → Presidio Anonymizer → sanitized-corpus
"""

import sys
import json
import hashlib
import hmac
import os
from pathlib import Path
from datetime import datetime
from collections import Counter

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# Permite importar reconocedores personalizados
sys.path.insert(0, str(Path(__file__).parent.parent / "recognizers"))

from ec_cedula import EcuadorCedulaRecognizer
from ec_ruc import EcuadorRucRecognizer
from ec_phone import EcuadorPhoneRecognizer


# ============================================================
# Configuración general
# ============================================================

INSTALL_SECRET = os.environ.get(
    "LAB1_HMAC_SECRET",
    "lab1-msp-default-secret"
)

SPACY_ES_MODEL = os.environ.get(
    "PRESIDIO_ES_MODEL",
    "es_core_news_sm"
)

ENTITIES = [
    "PERSON",
    "LOCATION",
    "EMAIL_ADDRESS",
    "EC_CEDULA",
    "EC_RUC",
    "EC_PHONE"
]


# ============================================================
# Seudonimización determinística
# ============================================================

def stable_token(value: str, entity_type: str) -> str:
    """
    Genera un token seudónimo determinístico.
    El mismo valor produce el mismo token para una misma instalación.
    """
    h = hmac.new(
        INSTALL_SECRET.encode("utf-8"),
        f"{entity_type}|{value}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"<{entity_type}_{h[:10]}>"


# ============================================================
# Construcción explícita del motor NLP en español
# ============================================================

def build_analyzer() -> AnalyzerEngine:
    """
    Crea un AnalyzerEngine de Presidio usando explícitamente spaCy en español.
    Esto evita el error KeyError: 'es'.
    """

    nlp_configuration = {
        "nlp_engine_name": "spacy",
        "models": [
            {
                "lang_code": "es",
                "model_name": SPACY_ES_MODEL
            }
        ]
    }

    provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
    nlp_engine = provider.create_engine()

    # Ajuste preventivo para documentos extensos
    if hasattr(nlp_engine, "nlp"):
        for _, nlp_model in nlp_engine.nlp.items():
            nlp_model.max_length = max(nlp_model.max_length, 2_000_000)

    analyzer_engine = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["es"]
    )

    analyzer_engine.registry.add_recognizer(EcuadorCedulaRecognizer())
    analyzer_engine.registry.add_recognizer(EcuadorRucRecognizer())
    analyzer_engine.registry.add_recognizer(EcuadorPhoneRecognizer())

    return analyzer_engine


analyzer = build_analyzer()
anonymizer = AnonymizerEngine()


# ============================================================
# Operadores de anonimización
# ============================================================

def build_operators():
    return {
        "PERSON": OperatorConfig(
            "custom",
            {
                "lambda": lambda value: stable_token(value, "PERSONA")
            }
        ),

        "EC_CEDULA": OperatorConfig(
            "custom",
            {
                "lambda": lambda value: stable_token(value, "CED")
            }
        ),

        "EC_RUC": OperatorConfig(
            "custom",
            {
                "lambda": lambda value: stable_token(value, "RUC")
            }
        ),

        "EC_PHONE": OperatorConfig(
            "mask",
            {
                "masking_char": "*",
                "chars_to_mask": 7,
                "from_end": True
            }
        ),

        "EMAIL_ADDRESS": OperatorConfig(
            "replace",
            {
                "new_value": "<EMAIL>"
            }
        ),

        "LOCATION": OperatorConfig(
            "replace",
            {
                "new_value": "<UBICACION>"
            }
        ),
    }


# ============================================================
# Sanitización de texto
# ============================================================

def sanitize_text(text: str) -> tuple[str, list]:
    if not text or not text.strip():
        return "", []

    results = analyzer.analyze(
        text=text,
        language="es",
        entities=ENTITIES
    )

    # Umbral mínimo para reducir falsos positivos
    results = [
        r for r in results
        if r.score >= 0.4
    ]

    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=build_operators()
    )

    audit = [
        {
            "entity": r.entity_type,
            "start": r.start,
            "end": r.end,
            "score": round(r.score, 3)
        }
        for r in results
    ]

    return anonymized.text, audit


def _count_by_type(entities: list) -> dict:
    return dict(Counter(e["entity"] for e in entities))


# ============================================================
# Procesamiento del corpus
# ============================================================

def process_corpus(input_dir: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    audit_log = []

    files = sorted(input_dir.glob("oficio_*.txt"))

    print(f"Procesando {len(files)} documentos...")

    for i, path in enumerate(files, start=1):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")

            sanitized, entities = sanitize_text(text)

            out_path = output_dir / path.name
            out_path.write_text(
                sanitized,
                encoding="utf-8"
            )

            audit_log.append({
                "file": path.name,
                "input_chars": len(text),
                "output_chars": len(sanitized),
                "entities_found": len(entities),
                "by_type": _count_by_type(entities),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

            if i % 50 == 0:
                print(f"  [{i}/{len(files)}] procesados")

        except Exception as exc:
            audit_log.append({
                "file": path.name,
                "error": str(exc),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

            print(f"ERROR procesando {path.name}: {exc}")

    audit_path = output_dir.parent / "logs" / "sanitize_audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    with open(audit_path, "w", encoding="utf-8") as f:
        for row in audit_log:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Auditoría escrita en {audit_path}")


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    base = Path(__file__).parent.parent

    process_corpus(
        base / "data" / "corpus",
        base / "data" / "sanitized"
    )
```

### E.2 Ejecutar el pipeline

```bash
cd ~/lab1
export LAB1_HMAC_SECRET="$(openssl rand -hex 32)"   # sal por sesión
python scripts/sanitize.py
```

Tiempo estimado: 3–7 minutos para 500 documentos.

### E.3 Verificación visual del resultado

```bash
diff data/corpus/oficio_0000_cardiologia.txt \
     data/sanitized/oficio_0000_cardiologia.txt | head -40
```

Salida esperada (extracto):
```
< Nombre: María González Pérez
> Nombre: <PERSONA_a3f2b1c98e>
< Cédula de identidad: 1710034065
> Cédula de identidad: <CED_8d2f1a0e44>
< Teléfono de contacto: 0987654321
> Teléfono de contacto: 098*******
< Correo electrónico: maria.123@correo.gob.ec
> Correo electrónico: <EMAIL>
```

### E.4 Validación cuantitativa de fuga

Crea `~/lab1/scripts/audit_leak.py`:

```python
#!/usr/bin/env python3
"""
Audita el corpus sanitizado en busca de PII residual.
Reporta cualquier coincidencia de:
- cédulas válidas (10 dígitos con checksum OK)
- teléfonos ecuatorianos válidos
- emails completos
- patrones de dirección obvios
"""
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "recognizers"))
from ec_cedula import EcuadorCedulaRecognizer

base = Path(__file__).parent.parent
sanitized_dir = base / "data" / "sanitized"
ced = EcuadorCedulaRecognizer()

leaks = {"cedula":0, "telefono":0, "email":0, "addr":0}
suspicious = []

for f in sanitized_dir.glob("oficio_*.txt"):
    text = f.read_text(encoding="utf-8")
    for m in re.finditer(r"\b\d{10}\b", text):
        if ced.validate_result(m.group()):
            leaks["cedula"] += 1
            suspicious.append((f.name, "cedula", m.group()))
    if re.search(r"\b09\d{8}\b", text):
        leaks["telefono"] += 1
    if re.search(r"[\w.-]+@[\w.-]+\.[a-z]{2,}", text):
        leaks["email"] += 1
    if re.search(r"\b(Av|Calle|Avenida|Av\.|Cl\.)\s+\w+", text):
        leaks["addr"] += 1

print("=== AUDITORÍA DE FUGA ===")
total = sum(leaks.values())
for k, v in leaks.items():
    status = "✓" if v == 0 else "✗"
    print(f"  {status} {k:10}: {v} ocurrencias")
print(f"\nTOTAL: {total} fugas en {len(list(sanitized_dir.glob('oficio_*.txt')))} documentos")

if suspicious[:10]:
    print("\nMuestra:")
    for s in suspicious[:10]:
        print(" ", s)
```

```bash
python scripts/audit_leak.py
```

Objetivo: total = 0 o muy próximo a 0. Si aparecen fugas, refinar los recognizers (típicamente el problema es falsos negativos del NER de spaCy en nombres exóticos).

### E.5 Subir corpus sanitizado a MinIO con retención WORM

```bash
# Subir el corpus
mc cp --recursive data/sanitized/ lab1/sanitized-corpus/

# Aplicar retención GOVERNANCE 30d a TODOS los objetos
# (paso obligatorio: la retención por defecto del bucket no se infiere fiablemente)
mc retention set --recursive GOVERNANCE 30d lab1/sanitized-corpus/

# Verificación: tomar muestra y confirmar
mc retention info lab1/sanitized-corpus/oficio_0000_cardiologia.txt
mc ls lab1/sanitized-corpus/ | wc -l
```

La aplicación de retención por objeto debe formar parte permanente del pipeline de ingesta del MSP. En un entorno de producción se delegaría a un *event handler* que escucha eventos `s3:ObjectCreated` en MinIO Notify y aplica la retención automáticamente.

---

## 10. MÓDULO F — ENTRENAMIENTO DIFERENCIALMENTE PRIVADO

### F.1 Preparación del dataset

Crea `~/lab1/scripts/prepare_dataset.py`:

```python
#!/usr/bin/env python3
import json
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

base = Path(__file__).parent.parent
sanitized = base / "data" / "sanitized"
manifest = base / "data" / "corpus" / "manifest.jsonl"

records = []
with open(manifest) as f:
    for line in f:
        m = json.loads(line)
        text = (sanitized / m["file"]).read_text(encoding="utf-8")
        records.append({"text": text, "label": m["label"]})

df = pd.DataFrame(records)
LABEL2ID = {l:i for i,l in enumerate(sorted(df.label.unique()))}
df["label_id"] = df.label.map(LABEL2ID)
print("Distribución:")
print(df.label.value_counts())

train, test = train_test_split(df, test_size=0.2, stratify=df.label, random_state=42)
train.to_parquet(base/"data"/"train.parquet", index=False)
test.to_parquet(base/"data"/"test.parquet", index=False)

with open(base/"data"/"label_map.json","w") as f:
    json.dump(LABEL2ID, f, indent=2)

print(f"Train={len(train)}, Test={len(test)}")
print(f"Labels: {LABEL2ID}")
```

```bash
python scripts/prepare_dataset.py
```

### F.2 Trainer con Opacus

Crea `~/lab1/scripts/train_dp.py`:

```python
#!/usr/bin/env python3
"""
Entrenamiento DP-SGD de clasificador BERT-Spanish sobre corpus sanitizado.
Garantía formal: (ε, δ)-DP con ε ≤ 3, δ = 1e-5.
"""
import json, time
from pathlib import Path
import pandas as pd, torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from opacus import PrivacyEngine
from opacus.utils.batch_memory_manager import BatchMemoryManager

BASE = Path(__file__).parent.parent
MODEL_NAME = "dccuchile/bert-base-spanish-wwm-cased"
MAX_LEN = 256
BATCH = 8                # físico
LOGICAL_BATCH = 64       # lógico (acumulación)
EPOCHS = 3
LR = 5e-5
TARGET_EPS = 3.0
TARGET_DELTA = 1e-5
MAX_GRAD_NORM = 1.0

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {device}")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
label_map = json.loads((BASE/"data"/"label_map.json").read_text())
NUM_LABELS = len(label_map)

class ClinicalDataset(Dataset):
    def __init__(self, parquet_path):
        self.df = pd.read_parquet(parquet_path).reset_index(drop=True)
    def __len__(self): return len(self.df)
    def __getitem__(self, i):
        row = self.df.iloc[i]
        enc = tokenizer(row["text"], truncation=True, padding="max_length",
                        max_length=MAX_LEN, return_tensors="pt")
        return {"input_ids": enc["input_ids"].squeeze(0),
                "attention_mask": enc["attention_mask"].squeeze(0),
                "labels": torch.tensor(int(row["label_id"]))}

train_ds = ClinicalDataset(BASE/"data"/"train.parquet")
test_ds  = ClinicalDataset(BASE/"data"/"test.parquet")
train_loader = DataLoader(train_ds, batch_size=BATCH, shuffle=True)
test_loader  = DataLoader(test_ds, batch_size=BATCH)

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME, num_labels=NUM_LABELS).to(device)

# Opacus exige que los parámetros requieran gradiente
optimizer = torch.optim.SGD(model.parameters(), lr=LR, momentum=0.9)

privacy_engine = PrivacyEngine()
model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model, optimizer=optimizer, data_loader=train_loader,
    target_epsilon=TARGET_EPS, target_delta=TARGET_DELTA,
    epochs=EPOCHS, max_grad_norm=MAX_GRAD_NORM,
)
print(f"Noise multiplier: {optimizer.noise_multiplier:.4f}")

def evaluate(loader):
    model.eval()
    correct, total = 0, 0
    with torch.no_grad():
        for batch in loader:
            ids = batch["input_ids"].to(device)
            mask = batch["attention_mask"].to(device)
            y = batch["labels"].to(device)
            out = model(input_ids=ids, attention_mask=mask)
            pred = out.logits.argmax(-1)
            correct += (pred == y).sum().item()
            total += y.size(0)
    return correct / total

start = time.time()
for epoch in range(EPOCHS):
    model.train()
    epoch_loss = 0.0
    with BatchMemoryManager(data_loader=train_loader,
                            max_physical_batch_size=BATCH,
                            optimizer=optimizer) as mloader:
        for step, batch in enumerate(mloader):
            optimizer.zero_grad()
            out = model(input_ids=batch["input_ids"].to(device),
                        attention_mask=batch["attention_mask"].to(device),
                        labels=batch["labels"].to(device))
            out.loss.backward()
            optimizer.step()
            epoch_loss += out.loss.item()
            if step % 20 == 0:
                eps = privacy_engine.get_epsilon(TARGET_DELTA)
                print(f"  epoch {epoch+1} step {step} loss={out.loss.item():.4f} ε={eps:.3f}")

    acc = evaluate(test_loader)
    eps = privacy_engine.get_epsilon(TARGET_DELTA)
    print(f"== epoch {epoch+1}: test_acc={acc:.4f}, ε={eps:.3f} ==")

print(f"Tiempo total: {(time.time()-start)/60:.1f} min")
print(f"ε final certificado: {privacy_engine.get_epsilon(TARGET_DELTA):.4f}")
print(f"δ:                   {TARGET_DELTA}")

# Guardar modelo (sin envoltura DP)
torch.save(model._module.state_dict(), BASE/"models"/"clinico_dp.pt")
print("Modelo guardado.")
```

### F.3 Baseline no privado para comparación

Crea una variante `~/lab1/scripts/train_baseline.py` idéntica pero sin `PrivacyEngine`, para medir la pérdida de utilidad atribuible a DP.

### F.4 Ejecución

```bash
mkdir -p models logs
python scripts/train_baseline.py 2>&1 | tee logs/baseline.log
python scripts/train_dp.py        2>&1 | tee logs/dp.log
```

En CPU el entrenamiento DP demora 2–4 horas; en GPU NVIDIA 10–30 min.

### F.5 Análisis comparativo

Tabla esperada (orden de magnitud):

| Modelo   | F1 (test) | ε    | δ    |
|----------|-----------|------|------|
| Baseline | 0.94      | ∞    | —    |
| DP ε=3   | 0.86      | 3.0  | 1e-5 |
| DP ε=8   | 0.91      | 8.0  | 1e-5 |

El estudiante debe argumentar dónde fijaría ε en producción.

---

## 11. MÓDULO G — CIFRADO HÍBRIDO Y CUSTODIA DE CLAVES

### G.1 Generación del par age

```bash
cd ~/lab1
age-keygen -o keys/master.key
chmod 600 keys/master.key
PUB=$(grep "public key" keys/master.key | awk '{print $NF}')
echo "Recipient: $PUB"
echo "$PUB" > keys/master.pub
```

### G.2 Empaquetar y cifrar el corpus sanitizado + modelo

```bash
tar -czf - data/sanitized/ models/clinico_dp.pt data/label_map.json \
  | age -r "$PUB" -o keys/corpus_v1.tar.gz.age

ls -lh keys/corpus_v1.tar.gz.age
file keys/corpus_v1.tar.gz.age
```

### G.3 Custodia de la clave privada en Vault

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root-token-lab1

vault kv put secret/lab1/age-master \
    private_key=@keys/master.key \
    public_key="$PUB" \
    created_at="$(date -u +%FT%TZ)" \
    classification="restricted" \
    owner="data-protection-officer@msp.gob.ec"

vault kv get secret/lab1/age-master
```

### G.4 Recuperación controlada (rol limitado)

Usa el token `age-reader` creado en A.5 (TTL 24h):

```bash
# Simular sesión de científico de datos
DS_TOKEN="<token emitido en A.5>"
VAULT_TOKEN=$DS_TOKEN vault kv get -field=private_key secret/lab1/age-master \
    > /tmp/recovered.key

# Descifrar
age -d -i /tmp/recovered.key keys/corpus_v1.tar.gz.age \
    | tar -xzv -C /tmp/restore/
```

Limpieza inmediata:
```bash
shred -u /tmp/recovered.key
```

### G.5 Rotación de claves

```bash
# Nueva llave maestra
age-keygen -o keys/master_v2.key
NEW_PUB=$(grep "public key" keys/master_v2.key | awk '{print $NF}')

# Re-cifrar payload con la nueva clave
age -d -i keys/master.key keys/corpus_v1.tar.gz.age \
    | age -r "$NEW_PUB" -o keys/corpus_v2.tar.gz.age

# Actualizar Vault (versión 2 de la entrada)
vault kv put secret/lab1/age-master \
    private_key=@keys/master_v2.key \
    public_key="$NEW_PUB" \
    rotated_from="v1" \
    created_at="$(date -u +%FT%TZ)"

vault kv metadata get secret/lab1/age-master
```

---

## 12. MÓDULO H — REPLICACIÓN Y VERIFICACIÓN CRIPTOGRÁFICA

### H.1 Hash de integridad antes de replicar

```bash
sha256sum keys/corpus_v2.tar.gz.age | tee keys/corpus_v2.sha256
```

### H.2 Replicación a sede secundaria (simulada)

```bash
mkdir -p ~/lab1/sede_b
cp keys/corpus_v2.tar.gz.age ~/lab1/sede_b/
cp keys/corpus_v2.sha256 ~/lab1/sede_b/
```

En el destino:
```bash
cd ~/lab1
sha256sum -c sede_b/corpus_v2.sha256 
```

### H.3 mTLS para canal de replicación (opcional avanzado)

Emite certificados desde Vault PKI:

```bash
vault write pki/roles/replicator \
    allowed_domains="lab1.local" \
    allow_subdomains=true max_ttl=720h

vault write -format=json pki/issue/replicator \
    common_name="sede-b.lab1.local" ttl=24h > keys/sede_b_cert.json

jq -r .data.certificate keys/sede_b_cert.json > keys/sede_b.crt
jq -r .data.private_key keys/sede_b_cert.json > keys/sede_b.key
```

Estos certificados se usarían en un canal rsync-over-TLS o syncthing autenticado.

---

## 13. MÓDULO I — AUDITORÍA DE FUGA RESIDUAL Y EVALUACIÓN DE IMPACTO

### I.1 Membership Inference contra el modelo DP

Crea `~/lab1/scripts/mia_attack.py`:

```python
#!/usr/bin/env python3
"""
Ataque de inferencia de membresía sobre el clasificador DP.
Hipótesis: si el modelo memoriza, los documentos de entrenamiento
tienen logits con menor entropía (mayor confianza) que los de hold-out.
"""
import json, torch, pandas as pd
from pathlib import Path
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import roc_auc_score
from scipy.stats import entropy

BASE = Path(__file__).parent.parent
MODEL_NAME = "dccuchile/bert-base-spanish-wwm-cased"
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
label_map = json.loads((BASE/"data"/"label_map.json").read_text())
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=len(label_map))
model.load_state_dict(torch.load(BASE/"models"/"clinico_dp.pt", map_location=device))
model.to(device).eval()

def conf(df):
    out = []
    for txt in df["text"]:
        enc = tokenizer(txt, truncation=True, padding=True, max_length=256, return_tensors="pt").to(device)
        with torch.no_grad():
            logits = model(**enc).logits.squeeze().cpu().numpy()
        probs = torch.softmax(torch.tensor(logits), dim=0).numpy()
        out.append(-entropy(probs))   # mayor → más confianza
    return out

train = pd.read_parquet(BASE/"data"/"train.parquet")
test  = pd.read_parquet(BASE/"data"/"test.parquet")

scores = conf(train) + conf(test)
labels = [1]*len(train) + [0]*len(test)
auc = roc_auc_score(labels, scores)
print(f"MIA AUC = {auc:.4f}")
print("Interpretación:",
      "✓ defendido (≤0.55)" if auc <= 0.55 else
      "⚠ moderado (0.55-0.65)" if auc <= 0.65 else "✗ fuga significativa")
```

```bash
python scripts/mia_attack.py
```

Un modelo DP con ε ≤ 3 debe arrojar AUC cercano a 0.50.

### I.2 Generación del Registro de Actividades de Tratamiento

Crea `~/lab1/scripts/gen_rat.py`:

```python
#!/usr/bin/env python3
"""
Genera el Registro de Actividades de Tratamiento conforme al
Art. 38 de la LOPDP-EC, en formato JSON estructurado.
"""
import json, hashlib
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).parent.parent
out = {
  "registro_id": "RAT-MSP-LAB1-2025-001",
  "version": "1.0",
  "fecha_emision": datetime.now(timezone.utc).isoformat(),
  "responsable_tratamiento": {
    "denominacion": "Ministerio de Salud Pública del Ecuador",
    "identificador_fiscal": "1768145480001",
    "delegado_proteccion_datos": "dpo@msp.gob.ec"
  },
  "finalidades": [
    "Clasificación automática de oficios clínicos para enrutamiento administrativo",
    "Entrenamiento de modelos de aprendizaje supervisado bajo garantía DP"
  ],
  "base_legitimadora": {
    "tipo": "obligacion_legal",
    "referencia": "Ley Orgánica de Salud, Art. 4; LOPDP Art. 7, lit. c"
  },
  "categorias_titulares": ["pacientes del sistema público de salud"],
  "categorias_datos": {
    "identificativos": ["nombre", "cédula", "domicilio", "teléfono", "correo"],
    "sensibles": ["diagnóstico", "medicación", "antecedentes clínicos"]
  },
  "destinatarios": ["Subsecretaría Nacional de Vigilancia de la Salud"],
  "transferencias_internacionales": "ninguna",
  "plazo_conservacion": "5 años desde el último acceso administrativo",
  "medidas_tecnicas": [
    "Sanitización con Microsoft Presidio 2.2 + recognizers locales EC",
    "Privacidad diferencial (ε=3, δ=1e-5) durante entrenamiento del modelo",
    "Cifrado age (X25519 + ChaCha20-Poly1305) en reposo",
    "Custodia de claves en HashiCorp Vault con RBAC y TTL 24h",
    "Verificación de integridad SHA-256 antes de replicación",
    "Object Lock GOVERNANCE 30 días en bucket sanitizado"
  ],
  "medidas_organizativas": [
    "Política de mínimo privilegio sobre Vault (age-reader)",
    "Auditoría automatizada de fuga residual (audit_leak.py)",
    "Rotación de claves cada 90 días",
    "Capacitación bianual al personal técnico"
  ],
  "evaluacion_impacto": {
    "requerida": True,
    "metodologia": "NIST SP 800-188",
    "riesgo_residual": "bajo",
    "mia_auc_post_dp": 0.51
  },
  "checksum_archivo": hashlib.sha256(
        (BASE/"keys"/"corpus_v2.tar.gz.age").read_bytes()).hexdigest()
}

(BASE/"reports"/"RAT.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))
print("RAT generado en reports/RAT.json")
```

```bash
python scripts/gen_rat.py
cat reports/RAT.json | jq
```

---

## 14. TROUBLESHOOTING CONSOLIDADO

| Síntoma | Causa probable | Resolución |
|---------|---------------|------------|
| `presidio-analyzer` no inicia | Falta descarga de modelo spaCy | `docker exec lab1-analyzer python -m spacy download es_core_news_lg` |
| `analyzer.analyze()` retorna lista vacía en español | Idioma no soportado en motor por defecto | Construir `NlpEngine` con configuración explícita `es` |
| Opacus error `Per sample gradient is not initialized` | Algún módulo del modelo no soporta hooks | Reemplazar capas con `ModuleValidator.fix(model)` antes de entrenar |
| OOM en GPU durante DP | Batch lógico demasiado grande | Reducir `LOGICAL_BATCH`, aumentar `BatchMemoryManager` max físico |
| Vault `permission denied` con token derivado | Política mal asignada | `vault token lookup` para verificar policies |
| age `no identity matched` | Clave privada corresponde a otra recipient | Verificar que `master.pub` coincida con la usada al cifrar |
| MinIO `Access Denied` | Alias del cliente mal configurado | `mc alias rm lab1 && mc alias set ...` |
| `mc rm` parece tener éxito pese a Object Lock | En buckets versionados, `mc rm` crea un delete marker; no elimina la versión real | Probar con `mc rm --version-id <id>` para atacar la versión protegida (ver A.4.4) |
| `mc rm --version-id` tiene éxito en objeto sin retención inferida | La retención por defecto del bucket NO se aplicó automáticamente al objeto (comportamiento inconsistente según versión de `mc`/MinIO) | Aplicar retención explícita post-upload: `mc retention set GOVERNANCE 30d <objeto>` o `--recursive` para el bucket entero |
| `mc retention info objeto` retorna `No retention configuration found` | El objeto se subió antes de fijar la política por defecto; la retención no es retroactiva | Resubir el objeto después de aplicar `mc retention set --default` |
| `mc rm --version-id` falla con `Object is WORM protected` | Comportamiento esperado: WORM está funcionando | Para borrado autorizado por DPO usar `--bypass-governance` |
| `mc ls --versions` muestra entrada `DEL` después de borrar | Comportamiento S3 estándar: delete marker, no borrado real | Eliminar el delete marker con `mc rm --version-id <DEL_VID>` para restaurar visibilidad |
| Pegar un bloque con `exit 1` cierra la terminal | `exit` termina la shell actual cuando se ejecuta fuera de un script | Sustituir `exit 1` por mensaje + `if/else`, o envolver el bloque en subshell `( ... )`, o guardar como `.sh` e invocar con `bash archivo.sh` |
| `mc retention set` falla con `Bucket is missing ObjectLockConfiguration` | El bucket se creó sin `--with-lock`; Object Lock no es activable retroactivamente | Aplicar el procedimiento de recuperación A.4.5: respaldar, `mc rb --force`, recrear con `mc mb --with-lock`, restaurar |
| `mc mb --with-lock` retorna `BucketAlreadyOwnedByYou` | El bucket ya existe (probablemente creado por `MINIO_DEFAULT_BUCKETS`) | Eliminar `MINIO_DEFAULT_BUCKETS` del compose, ejecutar `mc rb --force` y reintentar |
| Tika cuelga con PDFs grandes | Timeout del cliente | `requests.put(..., timeout=120)` |
| Recognizer EC_CEDULA no dispara | Score < threshold | Bajar `score_threshold` en `analyze()` o ajustar contexto |
| MIA AUC alto pese a DP | Dataset muy pequeño o ε real ≠ ε reportado | Verificar `get_epsilon()` post-training, no pre-training |

---

## 15. EJERCICIOS AVANZADOS Y EXTENSIONES DOCTORALES

### Nivel maestría

1. **E1** — Implementar un operador Presidio personalizado `FPE` (Format-Preserving Encryption) usando FF3-1 sobre cédulas para que el token preserve la longitud y se pueda revertir con clave maestra.
2. **E2** — Añadir un recognizer para historiales académicos del país (código SENESCYT).
3. **E3** — Reemplazar SHA-256 por HMAC con clave rotada y demostrar la propiedad de unlinkability entre datasets sanitizados con sales distintas.

### Nivel doctorado

4. **E4** — Diseñar un experimento factorial 2×3 (con/sin DP) × (ε ∈ {1, 3, 8}) midiendo F1 y MIA-AUC; aplicar ANOVA para determinar significancia.
5. **E5** — Sustituir DP-SGD por DP-Adam con corrección de momentos; comparar tasa de convergencia con análisis Rényi.
6. **E6** — Integrar un módulo de *secure multi-party computation* (SMPC) usando librerías como `crypten` para que tres hospitales puedan entrenar conjuntamente sin compartir corpus en claro.
7. **E7** — Probar adversarialmente el pipeline con documentos donde la PII está embebida en imágenes escaneadas (OCR-evasion) y proponer mitigaciones (Presidio Image Redactor + verificación cruzada).
8. **E8** — Formalizar el modelo de amenazas con LINDDUN-GO y mapear cada hallazgo a un control NIST SP 800-53.

---

## 16. RÚBRICA DE EVALUACIÓN

| Criterio | Excelente (90-100) | Aceptable (70-89) | Insuficiente (<70) | Peso |
|----------|--------------------|--------------------|---------------------|------|
| Reproducibilidad técnica | Pipeline ejecuta end-to-end sin intervención en máquina limpia | Requiere correcciones menores | No ejecuta o falta infraestructura | 20% |
| Cero fuga residual (O1) | audit_leak.py reporta 0 | ≤ 5 fugas justificadas | > 5 fugas | 15% |
| Certificación ε (O2) | ε ≤ 3 con accountant correcto | ε ≤ 5 documentado | ε no medido o > 8 | 15% |
| Análisis de utilidad (O3) | Tabla F1 + discusión cuantitativa | Solo métrica final | Sin medición | 10% |
| Cifrado y custodia (O4) | Rotación + RBAC + checksum funcionando | Cifrado básico age | Sin cifrado o claves expuestas | 15% |
| Registro de Tratamiento (O5) | RAT exhaustivo alineado Art. 38 | RAT parcial | Ausente | 10% |
| Auditoría adversarial (MIA) | AUC ≤ 0.55 demostrado | AUC ≤ 0.65 | AUC > 0.65 | 10% |
| Defensa oral | Justifica todas las decisiones arquitectónicas | Defensa parcial | No defiende | 5% |

---

## 17. REFERENCIAS NORMATIVAS Y TÉCNICAS

### Normativa

- Asamblea Nacional del Ecuador. **Ley Orgánica de Protección de Datos Personales**. Registro Oficial Suplemento No. 459, 26 de mayo de 2021.
- Presidencia de la República del Ecuador. **Reglamento General a la LOPDP**. Decreto Ejecutivo No. 904, 2023.
- Parlamento Europeo. **Reglamento (UE) 2016/679 (GDPR)**. DOUE L 119, 4 de mayo de 2016.

### Estándares técnicos

- ISO/IEC 27701:2019. *Privacy Information Management Systems — Requirements and guidelines*.
- ISO/IEC 20889:2018. *Privacy enhancing data de-identification terminology and classification of techniques*.
- NIST. SP 800-188. *De-Identifying Government Datasets: Techniques and Governance*. National Institute of Standards and Technology, 2023.
- NIST. SP 800-122. *Guide to Protecting the Confidentiality of Personally Identifiable Information*. 2010.
- NIST. SP 800-57 Part 1 Rev. 5. *Recommendation for Key Management*. 2020.

### Documentación oficial de herramientas

- Microsoft Presidio — Documentación oficial: `https://microsoft.github.io/presidio/`
- Microsoft Presidio — Repositorio: `https://github.com/microsoft/presidio`
- Meta AI — Opacus: `https://github.com/meta-pytorch/opacus` ; sitio: `https://opacus.ai/`
- FiloSottile — age: `https://github.com/FiloSottile/age` ; especificación: `https://age-encryption.org/v1`
- HashiCorp Vault — Documentación: `https://developer.hashicorp.com/vault/docs`
- MinIO — Documentación: `https://min.io/docs/minio/linux/index.html`
- Apache Tika — Documentación: `https://tika.apache.org/`
- spaCy — Documentación: `https://spacy.io/usage`
- Hugging Face Transformers — Documentación: `https://huggingface.co/docs/transformers`
- BETO (BERT en español, U. de Chile) — Modelo: `https://huggingface.co/dccuchile/bert-base-spanish-wwm-cased`

### Literatura formal indexada (selección)

- Dwork, C.; Roth, A. *The Algorithmic Foundations of Differential Privacy*. Foundations and Trends in Theoretical Computer Science, Vol. 9, Nos. 3–4, 2014.
- Abadi, M. et al. *Deep Learning with Differential Privacy*. Proceedings of the 23rd ACM Conference on Computer and Communications Security (CCS), 2016.
- Mironov, I. *Rényi Differential Privacy*. Proceedings of the 30th IEEE Computer Security Foundations Symposium (CSF), 2017.
- Shokri, R.; Stronati, M.; Song, C.; Shmatikov, V. *Membership Inference Attacks against Machine Learning Models*. Proceedings of the IEEE Symposium on Security and Privacy (S&P), 2017.
- Sweeney, L. *k-anonymity: a model for protecting privacy*. International Journal on Uncertainty, Fuzziness and Knowledge-based Systems, 10(5), 2002.

---

**FIN DEL MANUAL — LABORATORIO 1**
