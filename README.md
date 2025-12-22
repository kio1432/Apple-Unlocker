# Apple ID Account Manager

Проверка статуса Apple ID аккаунтов и смена пароля.

## Структура проекта

```
Apple-Unlocker/
├── checker.py           # Проверка статуса аккаунтов (iforgot.apple.com)
├── flow_unlocked.py     # Смена пароля через секретные вопросы
├── flow_login.py        # Смена пароля через авторизацию
├── requirements.txt     # Зависимости
└── files/
    ├── settings.json    # API ключ YesCaptcha
    ├── Accounts.txt     # Входные аккаунты
    └── results/         # Результаты по статусам
```

## Формат аккаунтов

```
email@example.com,password,answer1,answer2,answer3,MM/DD/YYYY
```

## Использование

### 1. Проверка статуса аккаунтов

```bash
python checker.py
```

Проверяет все аккаунты через iforgot.apple.com и сортирует по статусу:

| Статус | Описание | Действие |
|--------|----------|----------|
| valid | Аккаунт активен | Смена пароля через `flow_unlocked.py` или `flow_login.py` |
| valid_2fa | Требуется 2FA | Нужен доступ к доверенному устройству |
| invalid | Apple ID не существует | Проверить email |
| locked | Полная блокировка | Обращение в Apple Support |
| temp_locked | Временная блокировка IP | Сменить IP (VPN) и повторить |
| inactive | Аккаунт отключен | Невозможно восстановить |

Результаты: `files/results/[status].txt`

### 2. Смена пароля через секретные вопросы

```bash
python flow_unlocked.py
```

Использует iforgot.apple.com:
- Требует капчу (YesCaptcha)
- Требует дату рождения и ответы на секретные вопросы
- Работает даже если пароль неверный

### 3. Смена пароля через авторизацию

```bash
python flow_login.py
```

Использует appleid.apple.com:
- Не требует капчу
- Требует правильный пароль
- Быстрее чем iforgot flow
- Определяет статус: valid, 2FA, wrong_password, locked

## Конфигурация

`files/settings.json`:
```json
{
    "api_key": "YOUR_YESCAPTCHA_API_KEY"
}
```

## Коды ошибок Apple

| Код | Статус | Описание |
|-----|--------|----------|
| -20101 | invalid | Apple ID не существует |
| -20209 | locked | Аккаунт заблокирован |
| -20283 | locked | Аккаунт заблокирован |
| -20210 | inactive | Аккаунт неактивен |
| -20751 | inactive | Аккаунт неактивен |

## Flow через iforgot.apple.com

```
1. Загрузка iforgot.apple.com
2. Решение капчи (YesCaptcha)
3. Верификация Apple ID
4. GET /recovery/options
5. POST /recovery/options (reset_password)
6. GET /password/authenticationmethod
7. POST /password/authenticationmethod (questions)
8. GET/POST birthday
9. GET/POST questions
10. Установка нового пароля
```

## Flow через appleid.apple.com

```
1. Инициализация сессии
2. Авторизация (email + password)
3. Проверка статуса (2FA, locked)
4. Смена пароля через настройки
```
