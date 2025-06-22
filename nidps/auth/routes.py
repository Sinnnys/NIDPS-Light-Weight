from flask import render_template, redirect, url_for, flash, request, jsonify
from urllib.parse import urlparse
from flask_login import login_user, logout_user, current_user, login_required
from nidps import db
from nidps.auth import bp
from nidps.auth.forms import LoginForm, RegistrationForm, ChangePasswordForm, CreateUserForm, EditUserForm
from nidps.auth.models import User, Role
from nidps.auth.decorators import admin_required

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('web.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('auth.login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('web.index')
        return redirect(next_page)
    return render_template('auth/login.html', title='Sign In', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('web.index'))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('web.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if this is the first user (make them admin)
        is_first_user = User.query.count() == 0
        
        # Get or create roles
        admin_role = Role.query.filter_by(name='admin').first()
        user_role = Role.query.filter_by(name='user').first()
        
        if not admin_role:
            admin_role = Role()
            admin_role.name = 'admin'
            db.session.add(admin_role)
            db.session.commit()  # Commit to get the ID
        if not user_role:
            user_role = Role()
            user_role.name = 'user'
            db.session.add(user_role)
            db.session.commit()  # Commit to get the ID
        
        # Create user with appropriate role
        user = User()
        user.username = form.username.data
        user.email = form.email.data
        user.set_password(form.password.data)
        
        # First user becomes admin, others become regular users
        if is_first_user:
            user.role_id = admin_role.id
            flash('Congratulations! You are the first user and have been assigned admin privileges.')
        else:
            user.role_id = user_role.id
            flash('Congratulations, you are now a registered user!')
        
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', title='Register', form=form)

@bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Your password has been changed successfully.')
            return redirect(url_for('web.index'))
        else:
            flash('Current password is incorrect.')
    return render_template('auth/change_password.html', title='Change Password', form=form)

@bp.route('/users')
@admin_required
def users():
    """Admin page to manage users"""
    users_list = User.query.all()
    return render_template('auth/users.html', title='User Management', users=users_list)

@bp.route('/create_user', methods=['GET', 'POST'])
@admin_required
def create_user():
    """Admin page to create new users"""
    form = CreateUserForm()
    if form.validate_on_submit():
        # Get roles
        admin_role = Role.query.filter_by(name='admin').first()
        user_role = Role.query.filter_by(name='user').first()
        
        # Create user
        user = User()
        user.username = form.username.data
        user.email = form.email.data
        user.set_password(form.password.data)
        
        # Assign role
        if form.role.data == 'admin' and admin_role:
            user.role_id = admin_role.id
        elif user_role:
            user.role_id = user_role.id
        
        db.session.add(user)
        db.session.commit()
        flash(f'User {form.username.data} has been created successfully.')
        return redirect(url_for('auth.users'))
    
    return render_template('auth/create_user.html', title='Create User', form=form)

@bp.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    """Admin page to edit users"""
    user = User.query.get_or_404(user_id)
    form = EditUserForm(original_username=user.username, original_email=user.email)
    
    if form.validate_on_submit():
        # Get roles
        admin_role = Role.query.filter_by(name='admin').first()
        user_role = Role.query.filter_by(name='user').first()
        
        # Update user
        user.username = form.username.data
        user.email = form.email.data
        
        # Assign role
        if form.role.data == 'admin' and admin_role:
            user.role_id = admin_role.id
        elif user_role:
            user.role_id = user_role.id
        
        db.session.commit()
        flash(f'User {form.username.data} has been updated successfully.')
        return redirect(url_for('auth.users'))
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.role.data = user.role.name if user.role else 'user'
    
    return render_template('auth/edit_user.html', title='Edit User', form=form, user=user)

@bp.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Admin endpoint to delete users"""
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        return jsonify({'status': 'error', 'message': 'You cannot delete your own account.'})
    
    # Prevent deleting the last admin
    if user.role and user.role.name == 'admin':
        admin_count = User.query.join(Role).filter(Role.name == 'admin').count()
        if admin_count <= 1:
            return jsonify({'status': 'error', 'message': 'Cannot delete the last admin user.'})
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': f'User {username} has been deleted successfully.'}) 