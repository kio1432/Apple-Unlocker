# Apple ID Password Change Flows

## Обзор

Существует два основных сценария смены пароля Apple ID:

1. **Незаблокированный аккаунт** (`flow_unlocked.py`) - через секретные вопросы
2. **Заблокированный аккаунт** (`flow_locked.py`) - проверка статуса и рекомендации

---

## Flow 1: Незаблокированный аккаунт (flow_unlocked.py)

### Описание
Полный процесс смены пароля для аккаунтов с настроенными секретными вопросами.

### Этапы

```
┌─────────────────────────────────────────────────────────────┐
│  1. GET iforgot.apple.com/password/verify/appleid           │
│     └─> Получаем sstt токен и cookies                       │
├─────────────────────────────────────────────────────────────┤
│  2. GET /captcha?captchaType=IMAGE                          │
│     └─> Получаем капчу, решаем через YesCaptcha             │
├─────────────────────────────────────────────────────────────┤
│  3. POST /password/verify/appleid                           │
│     └─> Отправляем email + captcha token                    │
│     └─> Ответ: 302 redirect → /recovery/options             │
├─────────────────────────────────────────────────────────────┤
│  4. GET /recovery/options                                   │
│     └─> Получаем доступные опции восстановления             │
│     └─> JSON: {"recoveryOptions": ["reset_password", ...]}  │
├─────────────────────────────────────────────────────────────┤
│  5. POST /recovery/options                                  │
│     └─> Body: {"option": "reset_password"}                  │
│     └─> Ответ: 302 redirect → /password/authenticationmethod│
├─────────────────────────────────────────────────────────────┤
│  6. GET /password/authenticationmethod                      │
│     └─> Получаем доступные методы аутентификации            │
│     └─> JSON: {"authenticationMethods": ["questions", ...]} │
├─────────────────────────────────────────────────────────────┤
│  7. POST /password/authenticationmethod                     │
│     └─> Body: {"type": "questions"}                         │
│     └─> Ответ: 302 redirect → /password/verify/birthday     │
├─────────────────────────────────────────────────────────────┤
│  8. GET /password/verify/birthday                           │
│     └─> Получаем форму даты рождения                        │
│                                                             │
│  8b. POST /password/verify/birthday                         │
│     └─> Body: {"monthOfYear": "03", "dayOfMonth": "18",     │
│                "year": "1999"}                              │
│     └─> Ответ: 302 redirect → /password/verify/questions    │
├─────────────────────────────────────────────────────────────┤
│  9. GET /password/verify/questions                          │
│     └─> Получаем 2 секретных вопроса                        │
│     └─> JSON: {"questions": [{id, question, number}, ...]}  │
│                                                             │
│  9b. POST /password/verify/questions                        │
│     └─> Body: {"answers": [{id, answer}, {id, answer}]}     │
│     └─> Ответ: 302 redirect → /password/reset               │
├─────────────────────────────────────────────────────────────┤
│  10. GET /password/reset                                    │
│      └─> Форма нового пароля                                │
│                                                             │
│  10b. POST /password/reset                                  │
│      └─> Body: {"password": "NewPass123",                   │
│                 "confirmPassword": "NewPass123"}            │
│      └─> Ответ: 200/302 = УСПЕХ!                            │
└─────────────────────────────────────────────────────────────┘
```

### Использование

```bash
python flow_unlocked.py
```

### Формат Accounts.txt

```
email@example.com,OldPassword,Answer1,Answer2,Answer3,MM/DD/YYYY
```

---

## Flow 2: Заблокированный аккаунт (flow_locked.py)

### Описание
Проверка статуса блокировки аккаунта и определение возможных действий.

### Типы блокировок

| Статус | Код | Описание | Действие |
|--------|-----|----------|----------|
| **Permanent Lock** | -20209, -20283 | Полная блокировка | Обращение в Apple Support |
| **Temporary Lock** | session/timeout | Временная блокировка IP | Сменить IP/VPN |
| **Inactive** | -20210, -20751 | Аккаунт деактивирован | Невозможно восстановить |
| **Invalid** | -20101 | Apple ID не существует | Проверить email |
| **Rate Limited** | 503 | Слишком много запросов | Подождать |

### Этапы проверки

```
┌─────────────────────────────────────────────────────────────┐
│  1. GET iforgot.apple.com/password/verify/appleid           │
├─────────────────────────────────────────────────────────────┤
│  2. GET /captcha + решение                                  │
├─────────────────────────────────────────────────────────────┤
│  3. POST /password/verify/appleid                           │
│     │                                                       │
│     ├─> 302: Аккаунт НЕ заблокирован → deep check           │
│     │                                                       │
│     ├─> 503: Rate Limited                                   │
│     │                                                       │
│     └─> 4xx + error codes:                                  │
│         ├─> -20209/-20283: Permanent Lock                   │
│         ├─> -20210/-20751: Inactive                         │
│         └─> -20101: Invalid Apple ID                        │
├─────────────────────────────────────────────────────────────┤
│  Deep Check (если 302):                                     │
│  4. GET /recovery/options                                   │
│     │                                                       │
│     ├─> session/timeout в URL: Temporary Lock               │
│     │                                                       │
│     └─> recoveryOptions: Аккаунт можно разблокировать       │
└─────────────────────────────────────────────────────────────┘
```

### Использование

```bash
python flow_locked.py
```

### Результаты сохраняются в:
- `files/check_unlocked.txt` - можно разблокировать
- `files/check_locked.txt` - полная блокировка
- `files/check_temp_locked.txt` - временная блокировка
- `files/check_inactive.txt` - неактивные

---

## Важные заголовки

### Обязательные заголовки для всех запросов:

```python
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'en-US,en;q=0.9',
    'Content-Type': 'application/json',
    'Origin': 'https://iforgot.apple.com',
    'Referer': 'https://iforgot.apple.com/',
    'X-Requested-With': 'XMLHttpRequest',
    'sstt': '<token>'  # Обновляется на каждом шаге
}
```

### Sstt Token

- Получается из заголовка `Sstt` в ответе
- Также может быть в JSON ответе: `{"sstt": "..."}`
- **ВАЖНО**: Нужно URL-encode при использовании в заголовке
- Обновляется на КАЖДОМ шаге flow

---

## Cookies

Важные cookies:
- `idclient` - идентификатор клиента
- `ifssp` - сессия iforgot
- `X-Apple-I-Web-Token` - токен веб-сессии
- `dslang` - язык
- `site` - регион

---

## Секретные вопросы

Маппинг вопросов на индексы ответов:

| Вопрос (ключевые слова) | Индекс ответа |
|-------------------------|---------------|
| childhood friend, первый друг | 2 (Answer1) |
| first pet, первый питомец | 2 |
| dream job, идеальная работа | 3 (Answer2) |
| favorite book, любимая книга | 3 |
| parents meet, родители познакомились | 4 (Answer3) |
| first album, первый альбом | 4 |

---

## Файлы проекта

```
Apple-Unlocker/
├── flow_unlocked.py      # Flow для незаблокированных аккаунтов
├── flow_locked.py        # Проверка статуса блокировки
├── unlocker.py           # Основной скрипт (legacy)
├── checker.py            # Проверка статуса аккаунтов
├── debug_flow.py         # Детальная трассировка flow
├── FLOWS.md              # Эта документация
└── files/
    ├── Accounts.txt      # Входные аккаунты
    ├── settings.json     # Настройки (API key)
    ├── Success.txt       # Успешно обработанные
    ├── error.txt         # Ошибки
    └── check_*.txt       # Результаты проверки
```

---

## Примеры использования

### Проверить статус всех аккаунтов:
```bash
python flow_locked.py
```

### Сменить пароль незаблокированным:
```bash
python flow_unlocked.py
```

### Детальная отладка flow:
```bash
python debug_flow.py
```
