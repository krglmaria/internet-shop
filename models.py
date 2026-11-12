"""
models.py — классы ролевой модели доступа (RBAC).

Схема связей:
    Пользователь (User)  <-- многие-ко-многим -->  Роль (Role)
    Роль (Role)          <-- многие-ко-многим -->  Разрешение (Permission)

У пользователя НЕТ прав напрямую — только через роли.
"""
import hashlib
import hmac


def hash_password(password: str) -> str:
    """Возвращает SHA-256 хеш пароля (строка из 64 шестнадцатеричных символов)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class Permission:
    """Разрешение (право) — действие над ресурсом, например "catalog:read"."""

    def __init__(self, name: str, description: str = ""):
        self.name = name                # уникальный ключ права, например "users:ban"
        self.description = description  # описание для людей, например "Блокировка пользователей"

    # Два объекта Permission с одинаковым name — это одно и то же право.
    # __eq__ и __hash__ нужны, чтобы множество (set) не хранило дубликаты.
    def __eq__(self, other):
        return isinstance(other, Permission) and self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def __repr__(self):
        return f"Permission({self.name!r})"


class Role:
    """Роль — должность или функция (Клиент, Администратор и т.д.), набор прав."""

    def __init__(self, name: str):
        self.name = name
        self.permissions: set[Permission] = set()  # права этой роли

    def add_permission(self, permission: Permission):
        """Добавляет право в роль (повторное добавление ничего не меняет — это set)."""
        self.permissions.add(permission)

    def has_permission(self, permission_name: str) -> bool:
        """Есть ли у роли право с таким именем."""
        for perm in self.permissions:
            if perm.name == permission_name:
                return True
        return False

    # Роли сравниваются по имени
    def __eq__(self, other):
        return isinstance(other, Role) and self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def __repr__(self):
        return f"Role({self.name!r})"


class User:
    """Пользователь системы. Пароль хранится только в виде SHA-256 хеша."""

    def __init__(self, username: str, password_hash: str):
        self.username = username
        self.password_hash = password_hash  # НЕ сам пароль, а его хеш
        self.roles: set[Role] = set()       # роли пользователя (может быть несколько)

    def assign_role(self, role: Role):
        """Назначает пользователю роль."""
        self.roles.add(role)

    def check_password(self, password: str) -> bool:
        """Хеширует введённый пароль и сравнивает с сохранённым хешем.
        compare_digest сравнивает строки за одинаковое время (защита от атаки по времени)."""
        return hmac.compare_digest(self.password_hash, hash_password(password))

    def has_permission(self, permission_name: str) -> bool:
        """True, если право есть ХОТЯ БЫ У ОДНОЙ роли пользователя.
        Права всех ролей объединяются. Если ни одна роль права не даёт — False."""
        for role in self.roles:
            if role.has_permission(permission_name):
                return True
        return False

    def __repr__(self):
        role_names = sorted(r.name for r in self.roles)
        return f"User({self.username!r}, roles={role_names})"
