"""
rbac_stub.py — ВРЕМЕННАЯ заглушка вместо rbac.py.

Нужна только для того, чтобы main.py можно было запускать,
пока напарница пишет настоящие models.py и rbac.py.
Функции и классы повторяют контракт:
  load_system(path="data.json") -> dict[str, User]
  authenticate(users, username, password) -> User | None
  check_access(user, permission_name) -> bool
Когда появится rbac.py, main.py автоматически возьмёт его, а этот файл можно удалить.
"""

import hashlib
import json


def hash_password(password):
    """Возвращает SHA-256 хеш пароля в виде строки (как в контракте)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class Permission:
    """Право — действие над ресурсом, например 'catalog:read'."""

    def __init__(self, name, description):
        self.name = name
        self.description = description


class Role:
    """Роль — набор прав."""

    def __init__(self, name):
        self.name = name
        self.permissions = set()  # множество объектов Permission


class User:
    """Пользователь — хранит логин, хеш пароля и набор ролей."""

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash
        self.roles = set()  # множество объектов Role

    def has_permission(self, name):
        # Право есть, если оно есть хотя бы у одной из ролей
        for role in self.roles:
            for perm in role.permissions:
                if perm.name == name:
                    return True
        return False


def load_system(path="data.json"):
    """Читает data.json и собирает объекты. Возвращает словарь {логин: User}."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    # 1. Права
    permissions = {}
    for p in data["permissions"]:
        permissions[p["name"]] = Permission(p["name"], p["description"])

    # 2. Роли с правами
    roles = {}
    for r in data["roles"]:
        role = Role(r["name"])
        for perm_name in r["permissions"]:
            role.permissions.add(permissions[perm_name])
        roles[r["name"]] = role

    # 3. Пользователи с ролями (пароль сразу превращаем в хеш)
    users = {}
    for u in data["users"]:
        user = User(u["username"], hash_password(u["password"]))
        for role_name in u["roles"]:
            user.roles.add(roles[role_name])
        users[user.username] = user
    return users


def authenticate(users, username, password):
    """Возвращает пользователя, если логин и пароль верные, иначе None."""
    user = users.get(username)
    if user is not None and user.password_hash == hash_password(password):
        return user
    return None


def check_access(user, permission_name):
    """True — если у пользователя (через его роли) есть право, иначе False."""
    if user is None:
        return False
    return user.has_permission(permission_name)
