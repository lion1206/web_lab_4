import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from forms import RegistrationForm, LoginForm, CreateUserForm, EditUserForm, ChangePasswordForm
from models import User, Role
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlite3 import dbapi2 as sqlite
from extensions import db

# Инициализация приложения Flask
app = Flask(__name__)
app.config.from_object('config.Config')

# Инициализация базы данных
db.init_app(app)

#  проверки, что пользователь залогинен
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('logged_in') != True:
            return redirect(url_for('login', next=request.url))  # Перенаправление на страницу логина, если не авторизован
        return f(*args, **kwargs)
    return decorated_function

# Функция, которая выполняется до каждого запроса и загружает информацию о текущем пользователе из сессии
@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        try:
            g.user = db.session.get(User, session['user_id'])  # Получаем пользователя по ID из сессии
        except Exception:
            g.user = None

# Главная страница, на которой отображаются все пользователи
@app.route('/')
def index():
    users = User.query.all()  # Получаем всех пользователей
    roles = {role.id: role.name for role in Role.query.all()}  # Кэшируем роли
    return render_template('index.html', users=users, roles=roles)

# Страница регистрации нового пользователя
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)  # Создаем объект формы
    if request.method == 'POST' and form.validate():  # Если форма отправлена и валидна
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')  # Хешируем пароль
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            middle_name=form.middle_name.data,
            role_id=form.role_id.data  # Получаем роль из формы
        )
        db.session.add(new_user)  # Добавляем нового пользователя в сессию базы данных
        db.session.commit()  # Сохраняем изменения в базе данных
        flash('Спасибо за регистрацию!', 'success') 
        return redirect(url_for('login'))  # Перенаправляем на страницу логина
    return render_template('register.html', form=form)  

# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)  # Создаем объект формы для входа
    if request.method == 'POST' and form.validate():
        user = User.query.filter_by(username=form.username.data).first()  # Ищем пользователя по имени
        if user and check_password_hash(user.password, form.password.data):  # Проверяем правильность пароля
            session['logged_in'] = True  # Устанавливаем флаг авторизации
            session['user_id'] = user.id  # Сохраняем ID 
            flash('Успешный вход!', 'success')  
            next_url = request.args.get('next')  # Получаем параметр next, если он был в запросе
            return redirect(next_url or url_for('index'))  # Перенаправляем на главную или на исходную страницу
        else:
            flash('Неверное имя пользователя или пароль', 'error')  # Сообщение об ошибке, если логин или пароль неправильные
    return render_template('login.html', form=form) 

# Страница выхода
@app.route('/logout')
@login_required  # Убедитесь, что пользователь залогинен
def logout():
    session.pop('logged_in', None)  # Удаляем флаг
    session.pop('user_id', None)  # Удаляем ID 
    flash('Вы вышли из системы!', 'info')  # Показываем сообщение о выходе
    return redirect(url_for('index'))  # Перенаправляем на главную страницу

# Страница профиля пользователя
@app.route('/user/<int:user_id>')
def user_details(user_id):
    user = db.session.get(User, user_id)  # Получаем пользователя по ID
    if user:
        return render_template('user_details.html', user=user)  # Отображаем страницу с деталями пользователя
    else:
        flash('Пользователь не найден.', 'error')  # Сообщение об ошибке
        return redirect(url_for('index'))  # Перенаправляем на главную страницу

# Страница создания нового пользователя (доступна только администраторам)
@app.route('/user/create', methods=['GET', 'POST'])
@login_required
def create_user():
    form = CreateUserForm(request.form)  # Создаем форму для создания нового пользователя
    form.role_id.choices = [(role.id, role.name) for role in Role.query.all()]  # Загружаем роли из базы

    if request.method == 'POST' and form.validate():  # Если форма отправлена и валидна
        try:
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')  # Хешируем пароль
            new_user = User(
                username=form.username.data,
                password=hashed_password,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                middle_name=form.middle_name.data,
                role_id=form.role_id.data if form.role_id.data else None,
                created_at=datetime.utcnow()  # Устанавливаем дату создания пользователя
            )
            db.session.add(new_user)  # Добавляем нового пользователя в базу данных
            db.session.commit()  # Сохраняем изменения
            flash('Пользователь успешно создан!', 'success')  # Сообщение об успешном создании
            return redirect(url_for('index'))  # Перенаправляем на главную страницу
        except Exception as e:
            db.session.rollback()  # Откатываем изменения в случае ошибки
            flash(f'Ошибка создания пользователя: {e}', 'error')  # Сообщение об ошибке
            form.role_id.choices = [(role.id, role.name) for role in Role.query.all()]  # Повторно загружаем роли
    return render_template('create_user.html', form=form)  

# Страница редактирования данных пользователя
@app.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = db.session.get(User, user_id)  # Получаем пользователя по ID
    if not user:
        flash('Пользователь не найден.', 'error')  # Сообщение об ошибке, если пользователь не найден
        return redirect(url_for('index'))  # Перенаправляем на главную страницу

    form = EditUserForm(request.form, obj=user)  # Загружаем данные пользователя в форму
    form.role_id.choices = [(role.id, role.name) for role in Role.query.all()]  # Загружаем роли

    if request.method == 'POST' and form.validate():  # Если форма отправлена и валидна
        try:
            form.populate_obj(user)  # Заполняем объект пользователя из данных формы
            db.session.commit()  # Сохраняем изменения
            flash('Пользователь успешно обновлен!', 'success')  # Сообщение об успешном обновлении
            return redirect(url_for('index'))  # Перенаправляем на главную страницу
        except Exception as e:
            db.session.rollback()  # Откатываем изменения в случае ошибки
            flash(f'Ошибка обновления пользователя: {e}', 'error')  # Сообщение об ошибке
            form.role_id.choices = [(role.id, role.name) for role in Role.query.all()]  # Повторно загружаем роли
    return render_template('edit_user.html', form=form, user=user)  # Отображаем страницу редактирования пользователя

# Страница удаления пользователя
@app.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = db.session.get(User, user_id)  # Получаем пользователя по ID
    if not user:
        flash('Пользователь не найден.', 'error')  # Сообщение об ошибке, если пользователь не найден
        return redirect(url_for('index'))  # Перенаправляем на главную страницу

    try:
        db.session.delete(user)  # Удаляем пользователя
        db.session.commit()  # Сохраняем изменения
        flash('Пользователь успешно удален!', 'success')  # Сообщение об успешном удалении
    except Exception as e:
        db.session.rollback()  # Откатываем изменения в случае ошибки
        flash(f'Ошибка удаления пользователя: {e}', 'error')  # Сообщение об ошибке

    return redirect(url_for('index'))  # Перенаправляем на главную страницу

# Страница смены пароля
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm(request.form)  # Создаем форму для смены пароля
    if request.method == 'POST' and form.validate():  # Если форма отправлена и валидна
        user = g.user  # Получаем текущего пользователя
        if user and check_password_hash(user.password, form.old_password.data):  # Проверяем старый пароль
            hashed_password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')  # Хешируем новый пароль
            user.password = hashed_password  # Устанавливаем новый пароль
            db.session.commit()  # Сохраняем изменения
            flash('Пароль успешно изменен!', 'success')  # Сообщение об успешной смене пароля
            return redirect(url_for('index'))  # Перенаправляем на главную страницу
        else:
            flash('Неверный старый пароль', 'error')  # Сообщение об ошибке
    return render_template('change_password.html', form=form)  # Отображаем страницу смены пароля

# Обработчик ошибок
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404  # Страница 404

# Страница инициализации базы данных
@app.route('/initdb')
def initdb():
    """Initialize the database."""
    db.create_all()  # Создаем все таблицы базы данных

    # Проверяем, существуют ли роли
    if Role.query.count() == 0:
        # Создаем роли по умолчанию
        admin_role = Role(name='Admin', description='Administrator')
        user_role = Role(name='User', description='Regular User')

        db.session.add(admin_role)
        db.session.add(user_role)
        db.session.commit()

        print("Default roles created.")  # Выводим в консоль сообщение о создании ролей

    return "Database initialized (if not already)."  # Возвращаем строку о завершении инициализации базы данных

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)  # Запускаем приложение
