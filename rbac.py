"""
rbac.py — ядро системы: загрузка данных, вход в систему, проверка прав.

Публичные функции (контракт с main.py):
    load_system(path="data.json") -> dict[str, User]
    authenticate(users, username, password) -> User | None
    check_access(user, permission_name) -> bool
"""
import json

from models import Permission, Role, User, hash_password


class RBACConfigError(Exception):
    """Ошибка в файле данных: битый JSON, ссылка на несуществующую роль или право и т.п."""


def load_system(path: str = "data.json") -> dict:
    """Читает data.json, проверяет целостность и возвращает словарь {username: User}."""

    # --- 1. Читаем файл ---
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise RBACConfigError(f"Файл '{path}' не найден")
    except json.JSONDecodeError as e:
        raise RBACConfigError(f"В файле '{path}' ошибка формата JSON: {e}")

    # --- 2. Проверяем, что есть все три раздела ---
    for section in ("permissions", "roles", "users"):
        if not isinstance(data.get(section), list):
            raise RBACConfigError(f"В файле нет раздела '{section}' (должен быть список)")

    # --- 3. Создаём права ---
    permissions = {}  # имя права -> объект Permission
    for item in data["permissions"]:
        name = item.get("name")
        if not name:
            raise RBACConfigError("У одного из прав не заполнено поле 'name'")
        if name in permissions:
            raise RBACConfigError(f"Право '{name}' описано дважды")
        permissions[name] = Permission(name, item.get("description", ""))

    # --- 4. Создаём роли и привязываем к ним права ---
    roles = {}  # имя роли -> объект Role
    for item in data["roles"]:
        role_name = item.get("name")
        if not role_name:
            raise RBACConfigError("У одной из ролей не заполнено поле 'name'")
        if role_name in roles:
            raise RBACConfigError(f"Роль '{role_name}' описана дважды")
        role = Role(role_name)
        for perm_name in item.get("permissions", []):
            if perm_name not in permissions:
                raise RBACConfigError(
                    f"Роль '{role_name}' ссылается на несуществующее право '{perm_name}'"
                )
            role.add_permission(permissions[perm_name])
        roles[role_name] = role

    # --- 5. Создаём пользователей и назначаем им роли ---
    users = {}  # username -> объект User
    for item in data["users"]:
        username = item.get("username")
        password = item.get("password")
        if not username:
            raise RBACConfigError("У одного из пользователей не заполнено поле 'username'")
        if username in users:
            raise RBACConfigError(f"Пользователь '{username}' описан дважды")
        if not password:
            raise RBACConfigError(f"У пользователя '{username}' не задан пароль")
        role_names = item.get("roles", [])
        if not role_names:
            raise RBACConfigError(f"У пользователя '{username}' нет ни одной роли")

        # В память сохраняем только ХЕШ пароля, сам пароль дальше не используется
        user = User(username, hash_password(password))
        for role_name in role_names:
            if role_name not in roles:
                raise RBACConfigError(
                    f"Пользователь '{username}' ссылается на несуществующую роль '{role_name}'"
                )
            user.assign_role(roles[role_name])
        users[username] = user

    return users


def authenticate(users: dict, username: str, password: str):
    """Вход в систему. Возвращает User, если логин и пароль верны, иначе None."""
    user = users.get(username)
    if user is None:
        return None              # такого пользователя нет
    if user.check_password(password):
        return user              # хеш введённого пароля совпал с сохранённым
    return None                  # неверный пароль


def check_access(user, permission_name: str) -> bool:
    """Проверка доступа по принципу «запрещено всё, что не разрешено» (deny by default).
    Возвращает True только если право явно выдано одной из ролей пользователя."""
    if user is None:                          # не вошёл в систему — доступа нет
        return False
    if not isinstance(permission_name, str):  # некорректный запрос — доступа нет
        return False
    return user.has_permission(permission_name)
