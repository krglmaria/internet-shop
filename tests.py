"""
tests.py — автоматические тесты ядра RBAC (unittest).
Тесты используют СВОЙ временный JSON, поэтому не зависят от data.json напарницы.
Запуск:  python -m unittest -v tests
"""
import json
import os
import tempfile
import unittest

from rbac import RBACConfigError, authenticate, check_access, load_system

# Тестовые данные строго по контракту
TEST_DATA = {
    "permissions": [
        {"name": "catalog:read", "description": "Просмотр каталога"},
        {"name": "cart:manage", "description": "Корзина и оформление заказа"},
        {"name": "orders:process", "description": "Обработка заказов"},
        {"name": "products:write", "description": "Добавление и редактирование товаров"},
        {"name": "users:ban", "description": "Блокировка пользователей"},
    ],
    "roles": [
        {"name": "Клиент", "permissions": ["catalog:read", "cart:manage"]},
        {"name": "Менеджер по продажам", "permissions": ["catalog:read", "orders:process"]},
        {"name": "Контент-менеджер", "permissions": ["catalog:read", "products:write"]},
        {"name": "Администратор",
         "permissions": ["catalog:read", "orders:process", "products:write", "users:ban"]},
    ],
    "users": [
        {"username": "anna_client", "password": "client123", "roles": ["Клиент"]},
        {"username": "max_manager", "password": "manager123", "roles": ["Менеджер по продажам"]},
        {"username": "admin_root", "password": "admin123", "roles": ["Администратор"]},
        # пользователь с ДВУМЯ ролями
        {"username": "olga_multi", "password": "olga123",
         "roles": ["Менеджер по продажам", "Контент-менеджер"]},
    ],
}


def write_temp_json(data) -> str:
    """Записывает данные во временный файл и возвращает путь к нему."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    return path


class TestAccess(unittest.TestCase):
    """Проверка прав доступа."""

    @classmethod
    def setUpClass(cls):
        cls.path = write_temp_json(TEST_DATA)
        cls.users = load_system(cls.path)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.path)  # удаляем временный файл

    def test_client_cannot_ban(self):
        self.assertFalse(check_access(self.users["anna_client"], "users:ban"))

    def test_client_can_read_and_use_cart(self):
        client = self.users["anna_client"]
        self.assertTrue(check_access(client, "catalog:read"))
        self.assertTrue(check_access(client, "cart:manage"))

    def test_admin_can_everything_by_contract(self):
        admin = self.users["admin_root"]
        for perm in ("catalog:read", "orders:process", "products:write", "users:ban"):
            self.assertTrue(check_access(admin, perm), perm)
        # По контракту корзина только у Клиента, поэтому у админа её нет
        self.assertFalse(check_access(admin, "cart:manage"))

    def test_two_roles_union(self):
        olga = self.users["olga_multi"]
        self.assertTrue(check_access(olga, "orders:process"))   # от Менеджера
        self.assertTrue(check_access(olga, "products:write"))   # от Контент-менеджера
        self.assertFalse(check_access(olga, "users:ban"))       # ни одна роль не даёт
        self.assertFalse(check_access(olga, "cart:manage"))

    def test_unknown_permission_is_false(self):
        self.assertFalse(check_access(self.users["admin_root"], "nuclear:launch"))

    def test_none_user_is_false(self):
        self.assertFalse(check_access(None, "catalog:read"))


class TestAuth(unittest.TestCase):
    """Проверка входа в систему."""

    @classmethod
    def setUpClass(cls):
        cls.path = write_temp_json(TEST_DATA)
        cls.users = load_system(cls.path)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.path)

    def test_correct_password(self):
        user = authenticate(self.users, "admin_root", "admin123")
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "admin_root")

    def test_wrong_password(self):
        self.assertIsNone(authenticate(self.users, "admin_root", "qwerty"))

    def test_unknown_user(self):
        self.assertIsNone(authenticate(self.users, "hacker", "admin123"))

    def test_password_stored_as_hash(self):
        user = self.users["admin_root"]
        self.assertNotEqual(user.password_hash, "admin123")
        self.assertEqual(len(user.password_hash), 64)  # длина SHA-256 в hex


class TestIntegrity(unittest.TestCase):
    """Проверка понятных ошибок при испорченном data.json."""

    def load_broken(self, data):
        path = write_temp_json(data)
        try:
            with self.assertRaises(RBACConfigError) as ctx:
                load_system(path)
            return str(ctx.exception)
        finally:
            os.remove(path)

    def test_role_with_missing_permission(self):
        data = json.loads(json.dumps(TEST_DATA))  # глубокая копия
        data["roles"][0]["permissions"].append("fly:moon")
        message = self.load_broken(data)
        self.assertIn("fly:moon", message)

    def test_user_with_missing_role(self):
        data = json.loads(json.dumps(TEST_DATA))
        data["users"][0]["roles"] = ["Директор"]
        message = self.load_broken(data)
        self.assertIn("Директор", message)

    def test_missing_file(self):
        with self.assertRaises(RBACConfigError):
            load_system("net_takogo_faila.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
