"""
main.py — консольное меню интернет-магазина с ролевым доступом (RBAC).

Важно: доступ проверяется ТОЛЬКО через check_access(user, "право").
В меню нет проверок вида if role == "Администратор" — меню не знает
ничего о ролях, оно знает только, какое ПРАВО нужно для каждого пункта.
"""

# Функции ядра RBAC (модуль rbac.py)
from rbac import load_system, authenticate, check_access, RBACConfigError

MAX_ATTEMPTS = 3  # число попыток входа

# ---------- «База данных» магазина для имитации действий (только в памяти) ----------
catalog = ["Ноутбук — 350 000 тг", "Мышь — 5 000 тг", "Наушники — 15 000 тг"]
cart = []
orders = [{"id": 1, "status": "новый"}, {"id": 2, "status": "новый"}]
banned = set()  # логины заблокированных пользователей


# ---------- Действия (вызываются только после проверки права) ----------
def view_catalog(user, users):
    print("Каталог товаров:")
    for i, item in enumerate(catalog, 1):
        print(f"  {i}. {item}")


def manage_cart(user, users):
    view_catalog(user, users)
    choice = input("Номер товара для добавления в корзину: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(catalog):
        cart.append(catalog[int(choice) - 1])
        print(f"Добавлено. В корзине: {cart}")
    else:
        print("Неверный номер товара.")


def process_order(user, users):
    for order in orders:
        if order["status"] == "новый":
            order["status"] = "отправлен"
            print(f"Заказ №{order['id']}: статус изменён на «отправлен».")
            return
    print("Новых заказов нет.")


def add_product(user, users):
    name = input("Название и цена нового товара: ").strip()
    if name:
        catalog.append(name)
        print(f"Товар «{name}» добавлен в каталог.")
    else:
        print("Пустое название, товар не добавлен.")


def ban_user(user, users):
    login = input("Логин пользователя для блокировки: ").strip()
    if login == user.username:
        print("Нельзя заблокировать самого себя.")
    elif login in users:
        banned.add(login)
        print(f"Пользователь {login} заблокирован.")
    else:
        print("Такого пользователя нет.")


# ---------- Пункты меню: (текст, нужное право, функция) ----------
# Чтобы добавить новый пункт, достаточно дописать строку сюда —
# сам код проверки доступа менять не нужно.
MENU = [
    ("Посмотреть каталог",         "catalog:read",   view_catalog),
    ("Управлять корзиной",         "cart:manage",    manage_cart),
    ("Обработать заказ",           "orders:process", process_order),
    ("Добавить товар",             "products:write", add_product),
    ("Заблокировать пользователя", "users:ban",      ban_user),
]


def login(users):
    """Вход по логину и паролю, не более MAX_ATTEMPTS попыток."""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        username = input("Логин: ").strip()
        password = input("Пароль: ").strip()
        if username in banned:
            print("Учётная запись заблокирована.")
            continue
        user = authenticate(users, username, password)
        if user is not None:
            roles = ", ".join(sorted(r.name for r in user.roles))
            print(f"Добро пожаловать, {user.username}! Роли: {roles}")
            return user
        print(f"Неверный логин или пароль (попытка {attempt} из {MAX_ATTEMPTS}).")
    print("Попытки закончились. Программа завершена.")
    return None


def show_menu(user):
    print(f"\n=== Меню ({user.username}) ===")
    for i, (title, perm, _) in enumerate(MENU, 1):
        # Пометка ставится тоже через check_access
        mark = "" if check_access(user, perm) else " [нет доступа]"
        print(f"{i}. {title}{mark}")
    print("6. Сменить пользователя")
    print("0. Выход")


def main():
    # Если data.json битый или ссылается на несуществующую роль/право,
    # rbac.py бросает RBACConfigError. Показываем понятное сообщение
    # вместо длинной ошибки Python и не запускаем меню.
    try:
        users = load_system("data.json")
    except RBACConfigError as e:
        print(f"Ошибка загрузки данных: {e}")
        return
    print("Интернет-магазин.")
    user = login(users)
    while user is not None:
        show_menu(user)
        choice = input("Выбор: ").strip()
        if choice == "0":
            print("До свидания!")
            break
        if choice == "6":
            user = login(users)
            continue
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            title, perm, action = MENU[int(choice) - 1]
            # ГЛАВНАЯ ПРОВЕРКА: действие выполняется только при наличии права
            if check_access(user, perm):
                action(user, users)
            else:
                print(f"Access Denied: нет права {perm}")
        else:
            print("Нет такого пункта.")


if __name__ == "__main__":
    main()
