# 🍎 Apple-Unlocker - Гайд по запуску на macOS

## Требования
- Python 3.8+ (рекомендуется Python 3.13.5)
- macOS
- Интернет соединение

## Пошаговая инструкция

### 1. Открыть терминал
Нажмите `Cmd + Space`, введите "Terminal" и нажмите Enter

### 2. Перейти в папку проекта
```bash
cd /Users/admin/Documents/GitHub/Apple-Unlocker
```

### 3. Создать виртуальное окружение
```bash
python3 -m venv apple-unlocker-env
```

### 4. Активировать виртуальное окружение
```bash
source apple-unlocker-env/bin/activate
```
*После активации в начале строки терминала появится `(apple-unlocker-env)`*

### 5. Обновить pip (рекомендуется)
```bash
pip install --upgrade pip
```

### 6. Установить зависимости
```bash
pip install -r requirements.txt
```

### 7. Запустить проект
```bash
python unlocker.py
```

## Быстрый запуск (после первой настройки)

Если виртуальное окружение уже создано, для запуска достаточно:

```bash
cd /Users/admin/Documents/GitHub/Apple-Unlocker
source apple-unlocker-env/bin/activate
python unlocker.py
```

## Деактивация виртуального окружения

Когда закончите работу с проектом:
```bash
deactivate
```

## Возможные проблемы и решения

### ❌ ModuleNotFoundError: No module named 'tls_client'
**Решение:** Убедитесь, что виртуальное окружение активировано и зависимости установлены:
```bash
source apple-unlocker-env/bin/activate
pip install -r requirements.txt
```

### ❌ python: command not found
**Решение:** Используйте `python3` вместо `python`:
```bash
python3 -m venv apple-unlocker-env
python3 unlocker.py
```

### ❌ Permission denied
**Решение:** Убедитесь, что у вас есть права на запись в папку проекта

## Структура файлов конфигурации

После настройки убедитесь, что у вас есть:
- `files/settings.json` - настройки API и пароли
- `files/Accounts.txt` - данные аккаунтов (без пустых строк!)

## Проверка установки

Чтобы убедиться, что все установлено правильно:
```bash
source apple-unlocker-env/bin/activate
python -c "import tls_client, requests, colorama; print('✅ Все модули установлены успешно!')"
```

---
*Создано для проекта Apple-Unlocker*
