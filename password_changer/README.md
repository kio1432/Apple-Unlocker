# Apple ID Password Changer

Смена пароля Apple ID через различные методы.

## Методы

### 1. flow_unlocked.py (ГОТОВ)
Смена пароля через iforgot.apple.com с использованием секретных вопросов.

**Требования:**
- Аккаунт не заблокирован
- Известны ответы на секретные вопросы
- Известна дата рождения

### 2. flow_login.py (В РАЗРАБОТКЕ)
Смена пароля через SRP авторизацию + idmsa API.

**Статус:** Требует доработки fingerprint генератора.

## Установка

```bash
pip install -r requirements.txt
```

## Настройка

Создайте `files/settings.json`:
```json
{
    "api_key": "YOUR_YESCAPTCHA_API_KEY"
}
```

Создайте `files/Accounts.txt`:
```
email@example.com,password,answer1,answer2,answer3,MM/DD/YYYY
```

## Запуск

```bash
# Готовый метод через iforgot
python flow_unlocked.py

# Экспериментальный метод через SRP (в разработке)
python flow_login.py
```

## Результаты

- `files/Success.txt` - успешно обработанные аккаунты
- `files/error.txt` - ошибки
- `files/logs/` - логи

## Дополнительные файлы

- `apple_fingerprint.py` - генератор fingerprint для Apple API (в разработке)
