# Email Validator API

API de validação de emails com scoring — Python + Flask.

## O que faz

- Valida sintaxe (RFC 5322)
- Verifica MX records do domínio via DNS
- Deteta emails temporários/descartáveis (500+ domínios)
- Verifica via SMTP se a caixa existe
- Devolve score de 0–100 e razão da decisão

## Instalação local

```bash
pip install -r requirements.txt
python app.py
```

## Criar a tua primeira API key

```bash
curl -X POST http://localhost:5000/admin/keys \
  -H "X-Admin-Secret: muda-isto-para-algo-seguro" \
  -H "Content-Type: application/json" \
  -d '{"plan": "free"}'
```

Resposta:
```json
{"api_key": "ev_xxxxxxxxxxxxxxxx", "plan": "free"}
```

## Usar a API

### Validar um email (GET)
```bash
curl "http://localhost:5000/validate?email=test@gmail.com&api_key=ev_xxx"
```

### Validar um email (POST)
```bash
curl -X POST http://localhost:5000/validate \
  -H "X-API-Key: ev_xxx" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com"}'
```

### Resposta exemplo
```json
{
  "email": "test@gmail.com",
  "valid": true,
  "score": 90,
  "disposable": false,
  "checks": {
    "syntax": true,
    "mx_record": true,
    "smtp": true
  },
  "details": {
    "domain": "gmail.com",
    "mx_host": "gmail-smtp-in.l.google.com",
    "syntax_reason": null,
    "mx_reason": null,
    "smtp_reason": null
  },
  "plan": "free"
}
```

### Validação em batch (planos basic/pro)
```bash
curl -X POST http://localhost:5000/validate/batch \
  -H "X-API-Key: ev_xxx" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["a@gmail.com", "b@mailinator.com"]}'
```

## Limites por plano

| Plano  | Requests/dia | Batch |
|--------|-------------|-------|
| free   | 100         | Não   |
| basic  | 1.000       | Sim   |
| pro    | 10.000      | Sim   |

## Deploy no Render.com

1. Faz push para GitHub
2. Vai a render.com → New Web Service → liga o repo
3. O `render.yaml` configura tudo automaticamente
4. Tens a URL pública em 2 minutos

## Publicar no RapidAPI

1. Vai a rapidapi.com/provider
2. Cria uma nova API
3. Base URL = a tua URL do Render
4. Define os endpoints: `/validate` e `/validate/batch`
5. Configura planos e preços (ex: free 100/dia, basic 9$/mês, pro 29$/mês)
6. Publica — o RapidAPI gere os pagamentos e as API keys

## Adicionar mais domínios disposable

Edita o set `DISPOSABLE_DOMAINS` em `app.py`.
Podes também usar a lista open-source: https://github.com/disposable-email-domains/disposable-email-domains

## Diferencial vs competição

- Score de 0–100 (não só true/false)
- Campo `disposable` explícito
- `reason` em português/inglês por check falhado
- Endpoint batch sem overhead extra
- Preço abaixo das alternativas no RapidAPI
