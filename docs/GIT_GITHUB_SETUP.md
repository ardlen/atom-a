# Настройка Git для работы с GitHub

Ошибка `fatal: could not read Username for 'https://github.com': Device not configured` возникает, когда Git не может запросить учётные данные в текущем окружении. Ниже два способа решения.

---

## Способ 1: SSH (рекомендуется)

SSH-ключи не требуют ввода пароля при каждом push и работают из любого терминала.

### Шаг 1: Создать SSH-ключ

```bash
ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/id_ed25519 -N ""
```

Или интерактивно (с паролем для ключа):

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

### Шаг 2: Добавить ключ в ssh-agent

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

### Шаг 3: Скопировать публичный ключ и добавить в GitHub

```bash
cat ~/.ssh/id_ed25519.pub
# Скопируйте вывод (начинается с ssh-ed25519 ...)
```

1. GitHub → **Settings** → **SSH and GPG keys** → **New SSH key**
2. Вставьте скопированный ключ и сохраните.

### Шаг 4: Переключить remote на SSH

```bash
cd /Users/vitaliiardelyan/Development/sgw-registry
git remote set-url origin git@github.com:ardlen/atom-a.git
git push origin main
```

---

## Способ 2: HTTPS + Personal Access Token

Подходит, если хотите оставить HTTPS.

### Шаг 1: Создать токен на GitHub

1. GitHub → **Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)**
2. **Generate new token (classic)** → выберите scope `repo`
3. Скопируйте токен (показывается один раз).

### Шаг 2: Выполнить push в обычном терминале

Откройте **Terminal.app** (не встроенный терминал Cursor) и выполните:

```bash
cd /Users/vitaliiardelyan/Development/sgw-registry
git push origin main
```

При запросе:
- **Username:** ваш GitHub username (`ardlen` или ваш логин)
- **Password:** вставьте Personal Access Token (не пароль от аккаунта)

После успешного push macOS Keychain сохранит учётные данные для следующих операций.

---

## Проверка

```bash
git remote -v
# Для SSH: origin  git@github.com:ardlen/atom-a.git
# Для HTTPS: origin  https://github.com/ardlen/atom-a.git

git push origin main
```
