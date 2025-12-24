# Apple ID Account Status Checker (SRP)

Проверяет статус аккаунтов Apple ID через SRP авторизацию.

## Особенности

- ✅ **Без капчи** — бесплатно
- ✅ **Прокси ротация** — каждый аккаунт через новый прокси
- ✅ **Быстро** — 2 секунды между запросами

## Статусы аккаунтов

| Статус | Описание |
|--------|----------|
| valid | Пароль верный |
| valid_sq | Требует секретные вопросы |
| valid_2fa | Требует 2FA |
| wrong_password | Неверный пароль |
| locked | Заблокирован (можно восстановить через iForgot) |
| banned | Полный бан (нельзя восстановить) |
| temp_locked | Временная блокировка |
| not_found | Apple ID не существует |

## Установка

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Настройка

### 1. Аккаунты
Создайте `files/Accounts.txt`:
```
email@example.com,password,answer1,answer2,answer3,MM/DD/YYYY
```

### 2. Прокси (опционально)
Создайте `../proxys.txt` (в корне проекта):
```
host:port:user:pass
host:port:user:pass
```

## Запуск

```bash
source venv/bin/activate
python checker_srp.py
```

## Результаты

- `files/results/` — файлы по статусам
- `files/logs/` — логи
